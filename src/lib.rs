//! Spectrum implementation.
use futures::future::FutureExt;
use std::sync::Arc;
use tokio::sync::Barrier;

pub mod client;
pub mod crypto;
pub mod leader;
pub mod publisher;
pub mod worker;

pub mod config;
mod health;
mod quorum;

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_store = config::from_env()?;
    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();
    let shutdown = async move {
        barrier2.wait().await;
    };
    let _ = futures::join!(
        client::run(config_store.clone()).then(|_| { barrier.wait() }),
        worker::run(config_store.clone(), shutdown),
        publisher::run(),
        leader::run()
    );

    Ok(())
}
