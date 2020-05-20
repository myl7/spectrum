# encoding: utf8
# Conflicts with black, isort
# pylint: disable=bad-continuation,ungrouped-imports,line-too-long
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import math
import operator
import subprocess
import sys

from abc import ABC, abstractmethod
from contextlib import contextmanager, asynccontextmanager, nullcontext, closing
from dataclasses import dataclass, field, asdict
from functools import reduce
from itertools import chain, groupby, starmap, product
from operator import attrgetter
from subprocess import check_call, check_output
from tempfile import TemporaryDirectory, NamedTemporaryFile
from typing import *
from pathlib import Path

import asyncssh

from halo import Halo
from tenacity import retry, stop_after_attempt, wait_fixed, AsyncRetrying

Bytes = NewType("Bytes", int)
Bits = NewType("Bits", int)
Milliseconds = NewType("Milliseconds", int)
MachineType = NewType("MachineType", str)
Hostname = NewType("Hostname", str)
SHA = NewType("SHA", str)
AMI = NewType("AMI", str)
Region = NewType("Region", str)

# Need to update install.sh to change this
MAX_WORKERS_PER_MACHINE = 10
AWS_REGION = Region("us-east-2")
MAX_ATTEMPTS = 3


@dataclass(frozen=True)
class Machine:
    ssh: asyncssh.SSHClientConnection
    hostname: Hostname


@dataclass
class Setting:
    publisher: Machine
    workers: List[Machine]
    clients: List[Machine]


class Protocol(ABC):
    @property
    @abstractmethod
    def flag(self) -> str:
        ...

    @classmethod
    @abstractmethod
    def _from_dict(cls, data: Dict[str, Any]) -> Protocol:
        ...

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Protocol:
        assert len(data) == 1
        key = next(iter(data.keys()))
        subclasses = {cls.__name__: cls for cls in Protocol.__subclasses__()}
        subcls: Optional[Type[Protocol]] = subclasses.get(key, None)
        if subcls is None:
            raise ValueError(
                f"Invalid protocol {data}. Expected one of {list(subclasses.keys())}."
            )
        return subcls._from_dict(data[key])  # pylint: disable=protected-access


@dataclass(frozen=True)
class Symmetric(Protocol):
    security: Bytes = field(default=Bytes(16))

    @property
    def flag(self) -> str:
        return f"--security {self.security}"

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> Symmetric:
        return cls(**data)


@dataclass(frozen=True)
class Insecure(Protocol):
    parties: int = field(default=2)

    @property
    def flag(self) -> str:
        return "--no-security"

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> Insecure:
        return cls(**data)


@dataclass(frozen=True)
class SeedHomomorphic(Protocol):
    parties: int

    @property
    def flag(self) -> str:
        return f"--security-multi-key 16"

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> SeedHomomorphic:
        return cls(**data)


@dataclass(order=True, frozen=True)
class Environment:
    machine_type: MachineType
    client_machines: int
    worker_machines: int

    @property
    def total_machines(self) -> int:
        return self.client_machines + self.worker_machines + 1

    def to_setup(self, machines: List[Machine]) -> Setting:
        assert len(machines) == self.total_machines
        return Setting(
            publisher=machines[0],
            workers=machines[1 : self.worker_machines + 1],
            clients=machines[-self.client_machines :],
        )


@dataclass(frozen=True)
class Experiment:
    # TODO: should just be one machine type?
    clients: int
    channels: int
    message_size: Bytes
    machine_type: MachineType = field(default=MachineType("c5.9xlarge"))
    clients_per_machine: int = field(default=250)
    workers_per_machine: int = field(default=1)
    worker_machines_per_group: int = field(default=1)
    protocol: Protocol = field(default=Symmetric())

    @property
    def groups(self) -> int:
        if isinstance(self.protocol, Symmetric):
            return 2
        if isinstance(self.protocol, Insecure):
            return self.protocol.parties
        if isinstance(self.protocol, SeedHomomorphic):
            return self.protocol.parties
        raise TypeError(
            f"Invalid protocol {self.protocol}. "
            "Expected one of Symmetric, Insecure, SeedHomomorphic"
        )

    @property
    def group_size(self) -> int:
        return self.workers_per_machine * self.worker_machines_per_group

    def to_environment(self) -> Environment:
        client_machines = math.ceil(self.clients / self.clients_per_machine)
        worker_machines = self.worker_machines_per_group * self.groups
        return Environment(
            machine_type=self.machine_type,
            worker_machines=worker_machines,
            client_machines=client_machines,
        )

    @classmethod
    def from_dict(cls, data) -> Experiment:
        protocol = data.pop("protocol", None)
        if protocol is not None:
            data["protocol"] = Protocol.from_dict(protocol)
        return cls(**data)


def experiments_by_environment(
    experiments: List[Experiment]
) -> List[Tuple[Environment, List[Experiment]]]:
    experiments = sorted(experiments, key=Experiment.to_environment)
    by_environment = groupby(experiments, Experiment.to_environment)
    return [(k, list(v)) for k, v in by_environment]


@dataclass(frozen=True)
class Result:
    experiment: Experiment
    time: Milliseconds  # in millis; BREAKING CHANGE


def _format_var_args(var_dict):
    return reduce(operator.add, [["-var", f"{k}={v}"] for k, v in var_dict.items()])


@contextmanager
def terraform_cleanup(region: Region):
    try:
        yield
    finally:
        tf_vars = _format_var_args(
            {
                "region": region,  # must be the same
                "ami": "null",
                "instance_type": "null",
                "client_machine_count": 0,
                "worker_machine_count": 0,
            }
        )
        with Halo("[infrastructure] tearing down all resources") as spinner:
            check_call(
                ["terraform", "destroy", "-auto-approve"] + tf_vars,
                stdout=subprocess.DEVNULL,
            )
            spinner.succeed()


@contextmanager
def terraform(tf_vars):
    with TemporaryDirectory() as tmpdir:
        with Halo("[infrastructure] checking current state") as spinner:
            plan = Path(tmpdir) / "tfplan"
            tf_vars = _format_var_args(tf_vars)
            cmd = ["terraform", "plan", f"-out={plan}", "-no-color"] + tf_vars
            plan_output = check_output(cmd)
            changes = [l for l in plan_output.decode("utf8").split("\n") if "#" in l]

            if not changes:
                spinner.info("[infrastructure] no changes to apply")
                return
            spinner.succeed("[infrastructure] found changes to apply:")
            for change in changes:
                change = change.lstrip(" #")
                print(f"  • {change}")

        if changes:
            with Halo(
                "[infrastructure] applying changes (output in [terraform.log])"
            ) as spinner:
                with open("terraform.log", "w") as f:
                    cmd = [
                        "terraform",
                        "apply",
                        "-refresh=false",
                        "-auto-approve",
                        str(plan),
                    ]
                    check_call(cmd, stdout=f)
                spinner.succeed("[infrastructure] created")

        data = json.loads(check_output(["terraform", "output", "-json"]))
    yield {k: v["value"] for k, v in data.items()}


@dataclass(frozen=True)
class PackerBuild:
    timestamp: int
    region: Region
    ami: AMI
    machine_type: MachineType
    sha: SHA

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PackerBuild:
        region, _, ami = data["artifact_id"].partition(":")
        return cls(
            timestamp=data["build_time"],
            region=region,
            ami=ami,
            sha=data["custom_data"]["sha"],
            machine_type=data["custom_data"]["instance_type"],
        )


@dataclass(frozen=True)
class PackerManifest:
    # newest to oldest
    builds: List[PackerBuild]

    @classmethod
    def from_disk(cls, fname) -> PackerManifest:
        with open(fname) as f:
            data = json.load(f)
        builds = list(map(PackerBuild.from_dict, data["builds"]))
        builds.sort(key=attrgetter("timestamp"), reverse=True)
        return cls(builds)

    def most_recent_matching(
        self, machine_type: MachineType, sha: SHA
    ) -> Optional[PackerBuild]:
        for build in self.builds:
            if build.sha == sha and build.machine_type == machine_type:
                return build
        return None


def ensure_ami_build(
    machine_type: MachineType, sha: SHA, git_root: Path, force_rebuild=False
) -> PackerBuild:
    builds = PackerManifest.from_disk("manifest.json")
    build = builds.most_recent_matching(machine_type, sha)

    if build is not None and not force_rebuild:
        return build

    with TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / "spectrum-src.tar.gz"
        cmd = [
            "git",
            "archive",
            "--format",
            "tar.gz",
            "--output",
            str(src_path),
            "--prefix",
            "spectrum/",
            sha,
        ]
        check_call(cmd, cwd=git_root)

        packer_vars = _format_var_args(
            {
                "sha": sha,
                "src_archive": str(src_path),
                "instance_type": machine_type,
                "region": AWS_REGION,
            }
        )
        with open("packer.log", "w") as f:
            with Halo(
                "[infrastructure] building AMI (output in [packer.log])"
            ) as spinner:
                check_call(["packer", "build"] + packer_vars + ["image.json"], stdout=f)
                spinner.succeed()

    builds = PackerManifest.from_disk("manifest.json")
    build = builds.most_recent_matching(machine_type, sha)
    if build is None:
        raise RuntimeError("Packer did not create the expected build.")
    return build


def _get_git_root() -> Path:
    cmd = ["git", "rev-parse", "--show-toplevel"]
    return Path(check_output(cmd).decode("ascii").strip())


def _get_last_sha(git_root: Path) -> SHA:
    cmd = ["git", "rev-list", "-1", "HEAD", "--", "spectrum"]
    return SHA(check_output(cmd, cwd=git_root).decode("ascii").strip())


@asynccontextmanager
async def _connect_ssh(*args, **kwargs):
    reraise_err = None
    async for attempt in AsyncRetrying(wait=wait_fixed(2)):
        with attempt:
            async with asyncssh.connect(*args, **kwargs) as conn:
                # SSH may be ready but really the system isn't until this file exists.
                await conn.run(
                    "test -f /var/lib/cloud/instance/boot-finished", check=True
                )
                try:
                    yield conn
                except BaseException as err:  # pylint: disable=broad-except
                    # Exceptions from "yield" have nothing to do with us.
                    # We reraise them below without retrying.
                    reraise_err = err
    if reraise_err is not None:
        raise reraise_err from None


@asynccontextmanager
async def infra(environment: Environment, force_rebuild=False):
    Halo(f"[infrastructure] {environment}").stop_and_persist(symbol="•")

    git_root = _get_git_root()
    sha = _get_last_sha(git_root)

    build = ensure_ami_build(
        environment.machine_type, sha, git_root, force_rebuild=force_rebuild
    )

    tf_vars = {
        "ami": build.ami,
        "region": build.region,
        "instance_type": build.machine_type,
        "client_machine_count": environment.client_machines,
        "worker_machine_count": environment.worker_machines,
    }
    with terraform(tf_vars) as data:
        publisher = data["publisher"]
        workers = data["workers"]
        clients = data["clients"]
        ssh_key = asyncssh.import_private_key(data["private_key"])

        conn_ctxs = []
        conn_ctxs.append(
            _connect_ssh(
                publisher, known_hosts=None, client_keys=[ssh_key], username="ubuntu"
            )
        )
        for worker in workers:
            conn_ctxs.append(
                _connect_ssh(
                    worker, known_hosts=None, client_keys=[ssh_key], username="ubuntu"
                )
            )
        for client in clients:
            conn_ctxs.append(
                _connect_ssh(
                    client, known_hosts=None, client_keys=[ssh_key], username="ubuntu"
                )
            )

        async with contextlib.AsyncExitStack() as stack:
            with Halo("[infrastructure] connecting (SSH) to all machines") as spinner:
                conns = await asyncio.gather(*map(stack.enter_async_context, conn_ctxs))
                spinner.succeed("[infrastructure] connected (SSH)")
            hostnames = [publisher] + workers + clients
            machines = [
                Machine(ssh, hostname) for ssh, hostname in zip(conns, hostnames)
            ]
            setup = environment.to_setup(machines)

            with Halo("[infrastructure] starting etcd") as spinner:
                await setup.publisher.ssh.run(
                    "envsubst '$HOSTNAME' "
                    '    < "$HOME/config/etcd.template" '
                    "    | sudo tee /etc/default/etcd "
                    "    > /dev/null",
                    check=True,
                )
                await setup.publisher.ssh.run("sudo systemctl start etcd", check=True)
                # Make sure etcd is healthy
                async for attempt in AsyncRetrying(
                    wait=wait_fixed(2), stop=stop_after_attempt(20)
                ):
                    with attempt:
                        await setup.publisher.ssh.run(
                            f"ETCDCTL_API=3 etcdctl --endpoints {setup.publisher.hostname}:2379 endpoint health",
                            check=True,
                        )
                spinner.succeed("[infrastructure] etcd healthy")

            yield setup
        print()


async def _install_spectrum_config(machine: Machine, spectrum_config: Dict[str, Any]):
    spectrum_config_str = "\n".join([f"{k}={v}" for k, v in spectrum_config.items()])
    with NamedTemporaryFile() as tmp:
        tmp.write(spectrum_config_str.encode("utf8"))
        tmp.flush()
        await asyncssh.scp(tmp.name, (machine.ssh, "/tmp/spectrum.conf"))
    await machine.ssh.run(
        "sudo install -m 644 /tmp/spectrum.conf /etc/spectrum.conf", check=True
    )


async def _prepare_worker(
    machine: Machine,
    group: int,
    worker_start_idx: int,
    num_workers: int,
    etcd_env: Mapping[str, str],
):
    spectrum_config: Dict[str, Any] = {
        "SPECTRUM_WORKER_GROUP": group,
        "SPECTRUM_LEADER_GROUP": group,
        "SPECTRUM_WORKER_START_INDEX": worker_start_idx,
        **etcd_env,
    }
    await _install_spectrum_config(machine, spectrum_config)

    await machine.ssh.run(
        f"sudo systemctl start spectrum-worker@{{1..{num_workers}}}", check=True
    )
    await machine.ssh.run("sudo systemctl start spectrum-leader", check=True)


async def _prepare_client(
    machine: Machine, client_range: slice, etcd_env: Dict[str, Any]
):
    await _install_spectrum_config(machine, etcd_env)
    await machine.ssh.run(
        f"sudo systemctl start viewer@{{{client_range.start}..{client_range.stop}}}",
        check=True,
    )


async def _execute_experiment(
    publisher: Machine, etcd_env: Dict[str, Any]
) -> Milliseconds:
    await _install_spectrum_config(publisher, etcd_env)
    await publisher.ssh.run(
        "sudo systemctl start spectrum-publisher --wait", check=True
    )

    result = await publisher.ssh.run(
        "journalctl --unit spectrum-publisher "
        "    | grep -o 'Elapsed time: .*' "
        "    | sed 's/Elapsed time: \\(.*\\)ms/\\1/'",
        check=True,
    )
    result = int(result.stdout.strip())

    return result


async def run_experiment(
    experiment: Experiment, setup: Setting, spinner: Halo
) -> Milliseconds:
    try:
        publisher = setup.publisher
        workers = setup.workers
        clients = setup.clients

        etcd_url = f"etcd://{publisher.hostname}:2379"
        etcd_env = {"SPECTRUM_CONFIG_SERVER": etcd_url}

        spinner.text = "[experiment] setting up"
        # don't let this same output confuse us if we run on this machine again
        await publisher.ssh.run(
            "sudo journalctl --rotate && sudo journalctl --vacuum-time=1s", check=True
        )
        # ensure a blank slate
        await publisher.ssh.run(
            "ETCDCTL_API=3 etcdctl --endpoints localhost:2379 del --prefix ''",
            check=True,
        )
        # can't use ssh.run(env=...) because the SSH server doesn't like it.
        await publisher.ssh.run(
            f"SPECTRUM_CONFIG_SERVER={etcd_url} "
            "/home/ubuntu/spectrum/setup"
            f"    {experiment.protocol.flag}"
            f"    --channels {experiment.channels}"
            f"    --clients {experiment.clients}"
            f"    --group-size {experiment.group_size}"
            f"    --groups {experiment.groups}"
            f"    --message-size {experiment.message_size}",
            check=True,
            timeout=15,
        )

        spinner.text = "[experiment] starting workers and clients"
        assert experiment.workers_per_machine <= MAX_WORKERS_PER_MACHINE
        await asyncio.gather(
            *[
                _prepare_worker(
                    worker,
                    group + 1,
                    machine_idx * experiment.workers_per_machine,
                    experiment.workers_per_machine,
                    etcd_env,
                )
                for (machine_idx, group), worker in zip(
                    product(
                        range(experiment.worker_machines_per_group),
                        range(experiment.groups),
                    ),
                    workers,
                )
            ]
        )

        # Full client count at every machine except the last
        cpm = experiment.clients_per_machine
        client_counts = starmap(
            slice,
            zip(
                range(1, experiment.clients, cpm),
                chain(range(cpm, experiment.clients, cpm), [experiment.clients]),
            ),
        )
        await asyncio.gather(
            *[
                _prepare_client(client, client_range, etcd_env)
                for client, client_range in zip(clients, client_counts)
            ]
        )

        spinner.text = "[experiment] running"
        return await asyncio.wait_for(
            _execute_experiment(publisher, etcd_env), timeout=60.0
        )
    finally:
        spinner.text = "[experiment] shutting everything down"
        shutdowns = []
        for worker in workers:
            shutdowns.append(
                worker.ssh.run("sudo systemctl stop spectrum-leader", check=False)
            )
            shutdowns.append(
                worker.ssh.run("sudo systemctl stop 'spectrum-worker@*'", check=False)
            )
        shutdowns.append(
            publisher.ssh.run("sudo systemctl stop spectrum-publisher", check=False)
        )
        await asyncio.gather(*shutdowns)


@contextmanager
def stream_json(
    f: TextIO, close: bool = False
) -> Iterator[Callable[[Dict[str, Any]], None]]:
    """Streams JSON objects to a file-like object.

    Hack around the fact that json.dump doesn't allow streaming.
    At the conclusion,

    If close is True, The file will be closed on exit.

    >>> with stream_json(open("test.json", "w")) as writer:
    ...   writer.write({"a": 1})
    ...   writer.write({"a": 1})
    >>> with open("test.json", "r") as f:
    ...   f.read() == '[\n{"a": 1},\n{"b": 2}\n]\n'
    True

    Args:
        f: file-like object (in str mode)
        close: if True, the f will be
    Yields:
        callable that writes its argument to f
    """
    closer: ContextManager = closing(f) if close else nullcontext()
    with closer:
        f.write("[\n")
        first = True

        def writer(data):
            nonlocal first
            if not first:
                f.write(",\n")
            first = False
            json.dump(data, f)
            f.flush()

        yield writer
        f.write("\n]\n")


async def retry_experiment(
    experiment: Experiment, setting: Setting, writer: Callable[[Any], None]
):
    interrupted = False
    for attempt in range(MAX_ATTEMPTS):
        with Halo() as spinner:
            try:
                time = await run_experiment(experiment, setting, spinner)
            except asyncio.CancelledError:
                # On the first ^C for a given trial, just continue.
                # On the second, quit everything.
                if interrupted:
                    spinner.fail("Got ^C multiple times.")
                    raise
                spinner.fail("Got ^C; retrying (do it again to quit everything).")
                interrupted = True
            except Exception as err:  # pylint: disable=broad-except
                msg = f"Error (attempt {attempt} of {MAX_ATTEMPTS}): {err!r}."
                if attempt == MAX_ATTEMPTS:
                    spinner.fail(msg)
                    raise
                spinner.info(msg)
            else:
                spinner.succeed(f"[experiment] time: {time}ms")
                writer(asdict(Result(experiment, time)))
                return


async def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--force-rebuild", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument(
        "experiments_file", metavar="EXPERIMENTS_FILE", type=argparse.FileType("r")
    )
    parser.add_argument("--output", default="results.json", type=argparse.FileType("w"))
    args = parser.parse_args(args[1:])

    cleaner = terraform_cleanup(AWS_REGION) if args.cleanup else nullcontext()

    # TODO: progress bars using tqdm
    # https://stackoverflow.com/questions/37901292/asyncio-aiohttp-progress-bar-with-tqdm
    all_experiments = map(Experiment.from_dict, json.load(args.experiments_file))
    with stream_json(args.output, close=True) as writer:
        with cleaner:
            for environment, experiments in experiments_by_environment(all_experiments):
                async with infra(environment, args.force_rebuild) as setting:
                    for experiment in experiments:
                        print()
                        Halo(f"{experiment}").stop_and_persist(symbol="•")
                        await retry_experiment(experiment, setting, writer)


if __name__ == "__main__":
    try:
        asyncio.run(main(sys.argv))
    except KeyboardInterrupt:
        pass
