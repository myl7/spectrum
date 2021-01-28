use crate::{
    config::store::Store,
    experiment::Experiment,
    net::Config as NetConfig,
    protocols::{
        accumulator::Accumulator,
        wrapper::{ChannelKeyWrapper, ProtocolWrapper},
        Protocol,
    },
    services::{
        discovery::{register, Node},
        health::{wait_for_health, AllGoodHealthServer, HealthServer},
        quorum::wait_for_start_time_set,
        ClientInfo, WorkerInfo,
    },
};
use crate::{
    proto::{
        self, expect_field,
        worker_server::{Worker, WorkerServer},
        AggregateWorkerRequest, RegisterClientRequest, RegisterClientResponse, Share,
        UploadRequest, UploadResponse, VerifyRequest, VerifyResponse,
    },
    services::quorum::delay_until,
};
use std::time::Instant;

use futures::prelude::*;
use log::{error, info, trace, warn};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::sync::Arc;
use tokio::{spawn, sync::watch, sync::RwLock, task::spawn_blocking, time::sleep};
use tonic::{Request, Response, Status};

mod audit_registry;
mod client_registry;
mod service_registry;

use audit_registry::AuditRegistry;
use client_registry::Registry as ClientRegistry;
use service_registry::{Registry as ServiceRegistry, SharedClient};

type Error = crate::config::store::Error;
type BoxedError = Box<dyn std::error::Error + Sync + Send>;

struct WorkerState<P: Protocol> {
    audit_registry: AuditRegistry<P::AuditShare, P::WriteToken>,
    accumulator: Accumulator<Vec<P::Accumulator>>,
    experiment: Experiment,
    client_registry: ClientRegistry,
    protocol: P,
}

impl<P> WorkerState<P>
where
    P: Protocol,
    P::Accumulator: Clone,
{
    fn from_experiment(experiment: Experiment, protocol: P) -> Self {
        WorkerState {
            audit_registry: AuditRegistry::new(experiment.clients(), experiment.groups()),
            accumulator: Accumulator::new(protocol.new_accumulator()),
            experiment,
            client_registry: ClientRegistry::new(),
            protocol,
        }
    }
}

enum VerifyStatus<P: Protocol> {
    AwaitingShares,
    ShareVerified { clients: usize },
    AllClientsVerified { accumulator: Vec<P::Accumulator> },
}

impl<P> WorkerState<P>
where
    P: Protocol + 'static + Sync + Send + Clone,
    P::WriteToken: Clone + Send + fmt::Debug,
    P::AuditShare: Send + fmt::Debug,
    P::Accumulator: Send + Clone,
    P::ChannelKey: TryFrom<ChannelKeyWrapper> + Send,
    <P::ChannelKey as TryFrom<ChannelKeyWrapper>>::Error: fmt::Debug,
{
    async fn upload(&self, client: &ClientInfo, write_token: P::WriteToken) -> Vec<P::AuditShare> {
        trace!("upload() task for client_info: {:?}", client);
        self.audit_registry.init(&client, write_token.clone()).await;
        trace!("init'd for client_info: {:?}", client);

        let protocol = self.protocol.clone();
        let keys = self.experiment.get_keys(); // TODO(zjn): move into WorkerState
        let keys = keys
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<P::ChannelKey>, _>>()
            .unwrap();

        spawn_blocking(move || protocol.gen_audit(&keys, &write_token))
            .await
            .expect("Generating audit should not panic.")
    }

    async fn verify(
        &self,
        client: &ClientInfo,
        share: P::AuditShare,
    ) -> Result<VerifyStatus<P>, Error> {
        trace!("verify() task for client_info: {:?}", client);
        let check_count = self.audit_registry.add(client, share).await;
        trace!(
            "{}/{} shares received for {:?}",
            check_count,
            self.protocol.num_parties(),
            client.clone()
        );
        if check_count < self.protocol.num_parties() {
            return Ok(VerifyStatus::AwaitingShares);
        }
        trace!("Running verification.");

        let (token, shares) = self.audit_registry.drain(client).await;
        let protocol = self.protocol.clone();
        let verify = spawn_blocking(move || protocol.check_audit(shares))
            .await
            .unwrap();
        if !verify {
            warn!("Didn't verify");
            // TODO: fix serialization bugs
            // return None;
        }

        let protocol = self.protocol.clone();
        let accumulator = spawn_blocking(move || protocol.to_accumulator(token))
            .await
            .expect("Accepting write token should never fail.");

        if accumulator.len() != self.protocol.num_channels() {
            return Err(Error::new(&format!(
                "Invalid number of accumulator channels! {} != {}",
                accumulator.len(),
                self.protocol.message_len()
            )));
        }
        let accumulated_clients = self.accumulator.accumulate(accumulator).await;
        let total_clients = self.client_registry.num_clients().await;
        trace!("{}/{} clients", accumulated_clients, total_clients);

        if accumulated_clients == total_clients {
            Ok(VerifyStatus::AllClientsVerified {
                accumulator: self.accumulator.get().await,
            })
        } else {
            Ok(VerifyStatus::ShareVerified {
                clients: accumulated_clients,
            })
        }
    }

    async fn register_client(&self, client: &ClientInfo, shards: Vec<WorkerInfo>) {
        self.client_registry.register_client(client, shards).await;
    }
}

pub struct MyWorker<P: Protocol> {
    start_rx: watch::Receiver<Option<Instant>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    services: ServiceRegistry,
    state: Arc<WorkerState<P>>,
}

impl<P> MyWorker<P>
where
    P: Protocol,
    P::Accumulator: Clone,
{
    fn new(
        start_rx: watch::Receiver<Option<Instant>>,
        services: ServiceRegistry,
        experiment: Experiment,
        protocol: P,
    ) -> Self {
        let state = WorkerState::from_experiment(experiment, protocol);
        MyWorker {
            start_rx,
            start_time: Default::default(),
            services,
            state: Arc::new(state),
        }
    }

    async fn get_start_time(&self) -> Result<Instant, Error> {
        {
            let start_time_guard = self.start_time.read().await;
            if let Some(start_time) = *start_time_guard {
                return Ok(start_time);
            }
        }

        let start_lock = *self.start_rx.borrow();
        let start_time = start_lock
            .ok_or_else(|| Error::new("Verification request before experiment start time set."))?;

        let mut start_time_lock = self.start_time.write().await;
        *start_time_lock = Some(start_time);

        Ok(start_time)
    }

    async fn get_peers(&self, client: &ClientInfo) -> Result<Vec<SharedClient>, Status> {
        self.state
            .client_registry
            .get_peers(client)
            .await?
            .into_iter()
            .map(|info| self.services.get_worker(info))
            .collect()
    }

    fn check_not_started(&self) -> Result<(), Status> {
        let started = *self.start_rx.borrow();
        if started.is_some() {
            return Err(Status::failed_precondition(
                "Client registration after start time.",
            ));
        }

        Ok(())
    }
}

#[tonic::async_trait]
impl<P> Worker for MyWorker<P>
where
    P: Protocol + 'static + Sync + Send + Clone,
    P::WriteToken: Clone + TryFrom<proto::WriteToken> + Sync + Send + fmt::Debug,
    <P::WriteToken as TryFrom<proto::WriteToken>>::Error: fmt::Debug + Send,
    P::AuditShare: TryFrom<proto::AuditShare> + Into<proto::AuditShare> + Sync + Send + fmt::Debug,
    <P::AuditShare as TryFrom<proto::AuditShare>>::Error: fmt::Debug,
    P::ChannelKey: TryFrom<ChannelKeyWrapper> + Send,
    <P::ChannelKey as TryFrom<ChannelKeyWrapper>>::Error: fmt::Debug,
    P::Accumulator: Sync + Send + Clone + Into<Vec<u8>>,
{
    async fn upload(
        &self,
        request: Request<UploadRequest>,
    ) -> Result<Response<UploadResponse>, Status> {
        let request = request.into_inner();

        let client_id = expect_field(request.client_id, "Client ID")?;
        let client_info = ClientInfo::from(&client_id);
        trace!("upload() client_info: {:?}", &client_info);
        let write_token = expect_field(request.write_token, "Write Token")?;
        let state = self.state.clone();
        let peers: Vec<SharedClient> = self.get_peers(&client_info).await?;

        spawn(async move {
            let audit_shares = state
                .upload(&client_info, write_token.try_into().unwrap())
                .await;

            for (peer, audit_share) in peers.into_iter().zip(audit_shares.into_iter()) {
                let req = Request::new(VerifyRequest {
                    client_id: Some(client_id.clone()),
                    audit_share: Some(audit_share.into()),
                });
                spawn(async move {
                    peer.lock().await.verify(req).await.unwrap();
                });
            }
            Ok::<_, Status>(())
        });

        Ok(Response::new(UploadResponse {}))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let request = request.into_inner();

        // TODO(zjn): check which worker this comes from, don't double-insert
        let client_info = ClientInfo::from(&expect_field(request.client_id, "Client ID")?);
        let share = expect_field(request.audit_share, "Audit Share")?;
        let share = share.try_into().unwrap();
        let state = self.state.clone();
        let leader = self.services.get_my_leader();
        let start_time = self
            .get_start_time()
            .await
            .map_err(|e| Status::unavailable(e.message))?;

        spawn(async move {
            match state.verify(&client_info, share).await {
                Ok(VerifyStatus::AllClientsVerified { accumulator }) => {
                    let accumulator: Vec<Vec<u8>> =
                        accumulator.into_iter().map(Into::<Vec<u8>>::into).collect();
                    info!("Forwarding to leader.");
                    let req = Request::new(AggregateWorkerRequest {
                        share: Some(Share { data: accumulator }),
                    });
                    leader.lock().await.aggregate_worker(req).await.unwrap();
                }
                Ok(VerifyStatus::AwaitingShares) => {
                    // nothing to do
                }
                Ok(VerifyStatus::ShareVerified { clients }) => {
                    if clients % 10 == 0 {
                        let elapsed_ms: usize =
                            start_time.elapsed().as_millis().try_into().unwrap();
                        let qps: usize = (clients * 1000) / elapsed_ms;
                        info!(
                            "{} clients processed in time {}ms ({} qps)",
                            clients, elapsed_ms, qps
                        );
                    }
                }
                Err(err) => {
                    error!("Error during verification: {}", err)
                }
            }
        });

        Ok(Response::new(VerifyResponse {}))
    }

    async fn register_client(
        &self,
        request: Request<RegisterClientRequest>,
    ) -> Result<Response<RegisterClientResponse>, Status> {
        self.check_not_started()?;

        let request = request.into_inner();
        let client_info = ClientInfo::from(&expect_field(request.client_id, "Client ID")?);
        let shards = request.shards.into_iter().map(WorkerInfo::from).collect();
        self.state.register_client(&client_info, shards).await;

        let reply = RegisterClientResponse {};
        Ok(Response::new(reply))
    }
}

async fn inner_run<C, F, P>(
    config: C,
    experiment: Experiment,
    protocol: P,
    info: WorkerInfo,
    net: NetConfig,
    shutdown: F,
) -> Result<(), BoxedError>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
    P: Protocol + 'static + Sync + Send + Clone,
    P::WriteToken: Clone + TryFrom<proto::WriteToken> + Sync + Send + fmt::Debug,
    <P::WriteToken as TryFrom<proto::WriteToken>>::Error: fmt::Debug + Send,
    P::AuditShare: TryFrom<proto::AuditShare> + Into<proto::AuditShare> + Sync + Send + fmt::Debug,
    <P::AuditShare as TryFrom<proto::AuditShare>>::Error: fmt::Debug,
    P::ChannelKey: TryFrom<ChannelKeyWrapper> + Send,
    <P::ChannelKey as TryFrom<ChannelKeyWrapper>>::Error: fmt::Debug,
    P::Accumulator: Clone + Sync + Send + Into<Vec<u8>>,
{
    info!("Worker starting up.");

    let (start_tx, start_rx) = watch::channel(None);
    let (registry, registry_remote) = ServiceRegistry::new_with_remote();

    let worker = MyWorker::new(start_rx, registry, experiment, protocol);
    let server = tonic::transport::server::Server::builder()
        .add_service(HealthServer::new(AllGoodHealthServer::default()))
        .add_service(WorkerServer::new(worker))
        .serve_with_shutdown(net.local_socket_addr(), shutdown);

    let server_task = spawn(server);

    sleep(std::time::Duration::from_millis(500)).await;

    wait_for_health(format!("http://{}", net.public_addr())).await?;
    trace!("Worker {:?} healthy and serving.", info);
    register(&config, Node::new(info.into(), net.public_addr())).await?;

    let start_time = wait_for_start_time_set(&config).await.unwrap();
    registry_remote.init(info, &config).await?;
    delay_until(start_time).await;
    start_tx.send(Some(Instant::now()))?;

    server_task.await??;
    info!("Worker shutting down.");
    Ok(())
}

pub async fn run<C, F>(
    config: C,
    experiment: Experiment,
    protocol: ProtocolWrapper,
    info: WorkerInfo,
    net: NetConfig,
    shutdown: F,
) -> Result<(), BoxedError>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
{
    match protocol {
        ProtocolWrapper::Secure(protocol) => {
            inner_run(config, experiment, protocol, info, net, shutdown).await?;
        }
        ProtocolWrapper::SecureMultiKey(protocol) => {
            inner_run(config, experiment, protocol, info, net, shutdown).await?;
        }
        ProtocolWrapper::Insecure(protocol) => {
            inner_run(config, experiment, protocol, info, net, shutdown).await?;
        }
    }
    Ok(())
}
