//! Whole-server lifecycle management gRPC service.

use std::time::{Duration, SystemTime};

use claviron::runtime::{AppState, ApplicationBuild};
use claviron::supervisor::{
    MasterRuntimeSnapshot, ServerManager as DomainServerManager,
    ServerManagerError, WorkerLifecycle, WorkerManager,
};
use tonic::{Request, Response, Status};

use crate::proto::server::server_manager_server::{
    ServerManager, ServerManagerServer,
};
use crate::proto::server::{
    InfoRequest, InfoResponse, ProcessInfo, ReloadRequest, ReloadResponse,
    RunMode, ShutdownRequest, ShutdownResponse,
};

#[derive(Clone)]
pub struct ServerService {
    manager: DomainServerManager,
    state: AppState,
    capabilities: Vec<String>,
}

#[tonic::async_trait]
impl ServerManager for ServerService {
    async fn get_info(
        &self,
        _request: Request<InfoRequest>,
    ) -> Result<Response<InfoResponse>, Status> {
        let state = &self.state;
        let now = SystemTime::now();
        let started_at = timestamp(state.runtime_started_at());
        let uptime = duration(state.runtime_uptime());
        let primary = !state.is_worker();
        let mut info = InfoResponse {
            name: state.name().into(),
            environment: state.environment().into(),
            fleet_name: Some(state.fleet_name().into()),
            hostname: state.hostname().into(),
            claviron_version: claviron::runtime::VERSION.into(),
            application_version: state
                .registry_ref()
                .resolve::<ApplicationBuild>()
                .map(|build| build.version.clone()),
            started_at: primary.then_some(started_at).flatten(),
            uptime: primary.then_some(uptime).flatten(),
            reload_revision: primary.then_some(state.reload_count() as u64),
            responding_process: Some(ProcessInfo {
                run_mode: match state.run_mode() {
                    claviron::runtime::RunMode::Master => RunMode::Master,
                    claviron::runtime::RunMode::Worker(_) => RunMode::Worker,
                    claviron::runtime::RunMode::Standalone => {
                        RunMode::Standalone
                    }
                } as i32,
                pid: std::process::id(),
                worker_id: state.worker_id().map(u32::from),
                started_at,
                uptime,
                reload_revision: state.reload_count() as u64,
            }),
            capabilities: self.capabilities.clone(),
            captured_at: timestamp(now),
            ..Default::default()
        };
        if state.is_standalone() {
            info.workers_desired = Some(0);
            info.workers_running = Some(0);
            info.instance_id = Some(format!(
                "{}:{}",
                std::process::id(),
                state
                    .runtime_started_at()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|error| Status::internal(error.to_string()))?
                    .as_nanos()
            ));
        } else {
            match WorkerManager::new(state).and_then(|manager| manager.list()) {
                Ok(snapshot) => {
                    if state.is_worker()
                        && let Some(runtime) = snapshot.master_runtime
                    {
                        apply_master_runtime(&mut info, runtime);
                    }
                    info.workers_desired =
                        Some(u32::from(snapshot.workers_expected));
                    info.workers_running = Some(
                        snapshot
                            .workers
                            .iter()
                            .filter(|worker| {
                                worker.lifecycle() == WorkerLifecycle::Running
                            })
                            .count() as u32,
                    );
                    info.workers_captured_at = timestamp(snapshot.captured_at);
                    info.instance_id = snapshot.master.map(|master| {
                        format!(
                            "{}:{}:{}",
                            master.process().pid(),
                            master.process().started_at(),
                            master.generation()
                        )
                    });
                }
                Err(error) => {
                    // Identity remains available while authoritative membership
                    // is unavailable; stale/birth counts must not look current.
                    tracing::debug!(%error, "server info worker observation unavailable");
                }
            }
        }
        Ok(Response::new(info))
    }

    async fn reload(
        &self,
        _request: Request<ReloadRequest>,
    ) -> Result<Response<ReloadResponse>, Status> {
        let reloaded = self.manager.reload().await.map_err(manager_status)?;
        Ok(Response::new(ReloadResponse { revision: reloaded.revision() }))
    }

    async fn shutdown(
        &self,
        _request: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        self.manager.shutdown().map_err(manager_status)?;
        Ok(Response::new(ShutdownResponse {}))
    }
}

pub fn create_server_service(
    state: AppState,
    capabilities: Vec<String>,
) -> ServerManagerServer<ServerService> {
    ServerManagerServer::new(ServerService {
        manager: DomainServerManager::new(&state),
        state,
        capabilities,
    })
}

fn apply_master_runtime(
    info: &mut InfoResponse,
    runtime: MasterRuntimeSnapshot,
) {
    // The UTC Unix time and monotonic uptime belong to the same authoritative
    // supervisor capture, not the serving worker's local runtime.
    info.started_at = timestamp(
        SystemTime::UNIX_EPOCH
            + Duration::from_millis(runtime.started_at_unix_ms),
    );
    info.uptime = duration(runtime.uptime);
    info.reload_revision = Some(runtime.reload_revision);
}

fn timestamp(value: SystemTime) -> Option<prost_types::Timestamp> {
    let elapsed = value.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    Some(prost_types::Timestamp {
        seconds: i64::try_from(elapsed.as_secs()).ok()?,
        nanos: elapsed.subsec_nanos() as i32,
    })
}

fn duration(value: Duration) -> Option<prost_types::Duration> {
    Some(prost_types::Duration {
        seconds: i64::try_from(value.as_secs()).ok()?,
        nanos: value.subsec_nanos() as i32,
    })
}

fn manager_status(error: ServerManagerError) -> Status {
    match error {
        ServerManagerError::ShuttingDown
        | ServerManagerError::Signal { .. }
        | ServerManagerError::ReloadCompletionLagged(_)
        | ServerManagerError::ReloadCompletionClosed => {
            Status::unavailable(error.to_string())
        }
        ServerManagerError::InvalidControlPid(_) => {
            Status::internal(error.to_string())
        }
    }
}

#[cfg(test)]
#[path = "../../tests/server_info.rs"]
mod tests;
