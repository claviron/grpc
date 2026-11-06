//! Fixed worker-slot management gRPC service.
//!
//! A thin projection of the supervisor's snapshot onto the wire. The only rule
//! applied here is the master's own: `lifecycle` is what `WorkerStatus::
//! lifecycle()` derives from `phase` and `desired`, carried so every client
//! shows one label without re-implementing it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use claviron::runtime::AppState;
use claviron::supervisor::{
    BuildIdentity as DomainBuildIdentity, CommandKey,
    DrainReason as DomainDrainReason, ExitDisposition as DomainExitDisposition,
    ExitOutcome, FleetMode as DomainFleetMode,
    MasterIdentity as DomainMasterIdentity,
    OperationKind as DomainOperationKind,
    OperationOrigin as DomainOperationOrigin,
    WorkerBlockReason as DomainWorkerBlockReason, WorkerIntent,
    WorkerLifecycle as DomainWorkerLifecycle, WorkerListSnapshot,
    WorkerManager as DomainWorkerManager, WorkerManagerError,
    WorkerObservedPhase, WorkerOperation as DomainWorkerOperation,
    WorkerOwnership as DomainWorkerOwnership,
    WorkerStatus as DomainWorkerStatus, WorkerStatusSnapshot,
};
use claviron::sys::process::ProcessIdentity as DomainProcessIdentity;
use prost_types::{Duration as ProtoDuration, Timestamp};
use tonic::{Request, Response, Status};

use crate::proto::workers::worker_manager_server::{
    WorkerManager, WorkerManagerServer,
};
use crate::proto::workers::{
    BuildIdentity, FleetMode, ListWorkersRequest, ListWorkersResponse,
    MasterIdentity, ProcessIdentity, ReloadWorkersRequest,
    ReloadWorkersResponse, ResizeWorkersRequest, ResizeWorkersResponse,
    RestartWorkersRequest, RestartWorkersResponse, WorkerBlockReason,
    WorkerCommandRequest, WorkerCommandResponse, WorkerDesiredState,
    WorkerDrain, WorkerDrainReason, WorkerEnsureRunning, WorkerExitDisposition,
    WorkerLifecycle, WorkerManagementOrigin, WorkerOperation,
    WorkerOperationKind, WorkerOperationOrigin, WorkerOwnership, WorkerPhase,
    WorkerSignalOrigin, WorkerStatus, WorkerStatusRequest,
    WorkerStatusResponse, WorkerStopped, WorkerSupervisorOrigin,
    worker_desired_state, worker_operation_origin,
};

#[derive(Clone)]
pub struct WorkerService {
    state: AppState,
}

impl WorkerService {
    fn manager(&self) -> Result<DomainWorkerManager, Status> {
        DomainWorkerManager::new(&self.state).map_err(manager_status)
    }

    fn command(
        &self,
        request: Request<WorkerCommandRequest>,
        apply: impl FnOnce(
            &DomainWorkerManager,
            u8,
        ) -> Result<CommandKey, WorkerManagerError>,
    ) -> Result<Response<WorkerCommandResponse>, Status> {
        let worker_id = request.into_inner().worker_id;
        let worker_id = u8::try_from(worker_id)
            .map_err(|_| Status::invalid_argument("worker id exceeds uint8"))?;
        let command =
            apply(&self.manager()?, worker_id).map_err(manager_status)?;
        Ok(Response::new(WorkerCommandResponse {
            worker_id: u32::from(worker_id),
            accepted: true,
            submission_key: command.raw(),
        }))
    }
}

#[tonic::async_trait]
impl WorkerManager for WorkerService {
    async fn list_workers(
        &self,
        _request: Request<ListWorkersRequest>,
    ) -> Result<Response<ListWorkersResponse>, Status> {
        Ok(Response::new(snapshot_response(
            self.manager()?.list().map_err(manager_status)?,
        )?))
    }

    async fn get_worker_status(
        &self,
        request: Request<WorkerStatusRequest>,
    ) -> Result<Response<WorkerStatusResponse>, Status> {
        let worker_id = u8::try_from(request.into_inner().worker_id)
            .map_err(|_| Status::invalid_argument("worker id exceeds uint8"))?;
        Ok(Response::new(status_response(
            self.manager()?.status(worker_id).map_err(manager_status)?,
        )?))
    }

    async fn start_worker(
        &self,
        request: Request<WorkerCommandRequest>,
    ) -> Result<Response<WorkerCommandResponse>, Status> {
        self.command(request, DomainWorkerManager::start)
    }

    async fn stop_worker(
        &self,
        request: Request<WorkerCommandRequest>,
    ) -> Result<Response<WorkerCommandResponse>, Status> {
        self.command(request, DomainWorkerManager::stop)
    }

    async fn reload_worker(
        &self,
        request: Request<WorkerCommandRequest>,
    ) -> Result<Response<WorkerCommandResponse>, Status> {
        self.command(request, DomainWorkerManager::reload)
    }

    async fn restart_worker(
        &self,
        request: Request<WorkerCommandRequest>,
    ) -> Result<Response<WorkerCommandResponse>, Status> {
        self.command(request, DomainWorkerManager::restart)
    }

    async fn reload_workers(
        &self,
        _request: Request<ReloadWorkersRequest>,
    ) -> Result<Response<ReloadWorkersResponse>, Status> {
        let command =
            self.manager()?.reload_workers().map_err(manager_status)?;
        Ok(Response::new(ReloadWorkersResponse {
            accepted: true,
            submission_key: command.raw(),
        }))
    }

    async fn restart_workers(
        &self,
        _request: Request<RestartWorkersRequest>,
    ) -> Result<Response<RestartWorkersResponse>, Status> {
        let command =
            self.manager()?.restart_workers().map_err(manager_status)?;
        Ok(Response::new(RestartWorkersResponse {
            accepted: true,
            submission_key: command.raw(),
        }))
    }

    async fn add_worker(
        &self,
        _request: Request<ResizeWorkersRequest>,
    ) -> Result<Response<ResizeWorkersResponse>, Status> {
        let plan = self.manager()?.add_worker().map_err(manager_status)?;
        Ok(Response::new(resize_response(plan)))
    }

    async fn remove_worker(
        &self,
        _request: Request<ResizeWorkersRequest>,
    ) -> Result<Response<ResizeWorkersResponse>, Status> {
        let plan = self.manager()?.remove_worker().map_err(manager_status)?;
        Ok(Response::new(resize_response(plan)))
    }
}

pub fn create_worker_service(
    state: AppState
) -> Result<WorkerManagerServer<WorkerService>, Status> {
    Ok(WorkerManagerServer::new(WorkerService { state }))
}

fn snapshot_response(
    snapshot: WorkerListSnapshot
) -> Result<ListWorkersResponse, Status> {
    Ok(ListWorkersResponse {
        captured_at: Some(timestamp(snapshot.captured_at)?),
        workers_expected: u32::from(snapshot.workers_expected),
        workers: snapshot
            .workers
            .into_iter()
            .map(worker_status)
            .collect::<Result<_, _>>()?,
        master: snapshot.master.map(master_identity),
        fleet_mode: fleet_mode(snapshot.fleet_mode) as i32,
        build: Some(build_identity(snapshot.build)),
    })
}

fn status_response(
    snapshot: WorkerStatusSnapshot
) -> Result<WorkerStatusResponse, Status> {
    Ok(WorkerStatusResponse {
        captured_at: Some(timestamp(snapshot.captured_at)?),
        workers_expected: u32::from(snapshot.workers_expected),
        worker: Some(worker_status(snapshot.worker)?),
        master: snapshot.master.map(master_identity),
        fleet_mode: fleet_mode(snapshot.fleet_mode) as i32,
        build: Some(build_identity(snapshot.build)),
    })
}

fn worker_status(worker: DomainWorkerStatus) -> Result<WorkerStatus, Status> {
    Ok(WorkerStatus {
        worker_id: u32::from(worker.worker_id),
        lifecycle: lifecycle(worker.lifecycle()) as i32,
        uptime: worker.uptime.map(duration).transpose()?,
        recovery_attempts: worker.recovery_attempts,
        reload_revision: worker.reload_revision,
        incarnation: worker.incarnation,
        ownership: match worker.ownership {
            DomainWorkerOwnership::Unowned => WorkerOwnership::Unowned,
            DomainWorkerOwnership::Spawned => WorkerOwnership::Spawned,
            DomainWorkerOwnership::Adopted => WorkerOwnership::Adopted,
        } as i32,
        process: worker.process.map(process_identity),
        phase: phase(worker.phase) as i32,
        phase_age: Some(duration(worker.phase_age)?),
        desired: Some(desired_state(worker.desired)),
        desired_age: Some(duration(worker.desired_age)?),
        operation: worker.operation.map(operation).transpose()?,
        heartbeat_age: worker.heartbeat_age.map(duration).transpose()?,
        block_reason: worker
            .block_reason
            .map_or(WorkerBlockReason::Unspecified, block_reason)
            as i32,
    })
}

fn lifecycle(value: DomainWorkerLifecycle) -> WorkerLifecycle {
    match value {
        DomainWorkerLifecycle::Starting => WorkerLifecycle::Starting,
        DomainWorkerLifecycle::Running => WorkerLifecycle::Running,
        DomainWorkerLifecycle::Reloading => WorkerLifecycle::Reloading,
        DomainWorkerLifecycle::Stopping => WorkerLifecycle::Stopping,
        DomainWorkerLifecycle::Stopped => WorkerLifecycle::Stopped,
        DomainWorkerLifecycle::Exited => WorkerLifecycle::Exited,
        DomainWorkerLifecycle::Crashed => WorkerLifecycle::Crashed,
        DomainWorkerLifecycle::Unclaimed => WorkerLifecycle::Unclaimed,
    }
}

fn phase(value: WorkerObservedPhase) -> WorkerPhase {
    match value {
        WorkerObservedPhase::Unclaimed => WorkerPhase::Unclaimed,
        WorkerObservedPhase::OwnershipPending => WorkerPhase::OwnershipPending,
        WorkerObservedPhase::ReconciliationBlocked => {
            WorkerPhase::ReconciliationBlocked
        }
        WorkerObservedPhase::Starting => WorkerPhase::Starting,
        WorkerObservedPhase::Running => WorkerPhase::Running,
        WorkerObservedPhase::Reloading => WorkerPhase::Reloading,
        WorkerObservedPhase::DrainAcknowledged => {
            WorkerPhase::DrainAcknowledged
        }
        WorkerObservedPhase::TeardownCompleted => {
            WorkerPhase::TeardownCompleted
        }
        WorkerObservedPhase::Exited(ExitOutcome::Planned) => {
            WorkerPhase::ExitedPlanned
        }
        WorkerObservedPhase::Exited(ExitOutcome::Failed) => {
            WorkerPhase::ExitedFailed
        }
    }
}

fn desired_state(value: WorkerIntent) -> WorkerDesiredState {
    use worker_desired_state::State;

    let state = match value {
        WorkerIntent::EnsureRunning => {
            State::EnsureRunning(WorkerEnsureRunning {})
        }
        WorkerIntent::Stopped => State::Stopped(WorkerStopped {}),
        WorkerIntent::Drain { reason, after_exit } => {
            State::Drain(WorkerDrain {
                reason: match reason {
                    DomainDrainReason::Shutdown => WorkerDrainReason::Shutdown,
                    DomainDrainReason::ScaleDown => {
                        WorkerDrainReason::ScaleDown
                    }
                    DomainDrainReason::Rotation => WorkerDrainReason::Rotation,
                    DomainDrainReason::HeartbeatTimeout => {
                        WorkerDrainReason::HeartbeatTimeout
                    }
                    DomainDrainReason::ManualStop => {
                        WorkerDrainReason::ManualStop
                    }
                    DomainDrainReason::RollingRestart => {
                        WorkerDrainReason::RollingRestart
                    }
                } as i32,
                after_exit: match after_exit {
                    DomainExitDisposition::StayStopped => {
                        WorkerExitDisposition::StayStopped
                    }
                    DomainExitDisposition::Replace => {
                        WorkerExitDisposition::Replace
                    }
                    DomainExitDisposition::RemoveSlot => {
                        WorkerExitDisposition::RemoveSlot
                    }
                    DomainExitDisposition::FinishFleetShutdown => {
                        WorkerExitDisposition::FinishFleetShutdown
                    }
                } as i32,
            })
        }
    };
    WorkerDesiredState { state: Some(state) }
}

fn operation(value: DomainWorkerOperation) -> Result<WorkerOperation, Status> {
    let (kind, resize_from, resize_to) = match value.kind {
        DomainOperationKind::Start => (WorkerOperationKind::Start, 0, 0),
        DomainOperationKind::Stop => (WorkerOperationKind::Stop, 0, 0),
        DomainOperationKind::Restart => (WorkerOperationKind::Restart, 0, 0),
        DomainOperationKind::Reload => (WorkerOperationKind::Reload, 0, 0),
        DomainOperationKind::Rotation => (WorkerOperationKind::Rotation, 0, 0),
        DomainOperationKind::HeartbeatRecovery => {
            (WorkerOperationKind::HeartbeatRecovery, 0, 0)
        }
        DomainOperationKind::CrashRecovery => {
            (WorkerOperationKind::CrashRecovery, 0, 0)
        }
        DomainOperationKind::ReloadAll => {
            (WorkerOperationKind::ReloadAll, 0, 0)
        }
        DomainOperationKind::RestartAll => {
            (WorkerOperationKind::RestartAll, 0, 0)
        }
        DomainOperationKind::Resize { from, to } => {
            (WorkerOperationKind::Resize, u32::from(from), u32::from(to))
        }
        DomainOperationKind::ConfigReload => {
            (WorkerOperationKind::ConfigReload, 0, 0)
        }
        DomainOperationKind::FleetShutdown => {
            (WorkerOperationKind::FleetShutdown, 0, 0)
        }
    };
    Ok(WorkerOperation {
        id: value.id.raw(),
        kind: kind as i32,
        resize_from,
        resize_to,
        origin: Some(operation_origin(value.origin)),
        age: Some(duration(value.age)?),
    })
}

fn operation_origin(value: DomainOperationOrigin) -> WorkerOperationOrigin {
    use worker_operation_origin::Origin;

    let origin = match value {
        DomainOperationOrigin::Management { via_worker, command } => {
            Origin::Management(WorkerManagementOrigin {
                via_worker: via_worker.map(|worker| u32::from(worker.raw())),
                submission_key: command.raw(),
            })
        }
        DomainOperationOrigin::Supervisor => {
            Origin::Supervisor(WorkerSupervisorOrigin {})
        }
        DomainOperationOrigin::Signal => Origin::Signal(WorkerSignalOrigin {}),
    };
    WorkerOperationOrigin { origin: Some(origin) }
}

fn block_reason(value: DomainWorkerBlockReason) -> WorkerBlockReason {
    match value {
        DomainWorkerBlockReason::StalePresence => {
            WorkerBlockReason::StalePresence
        }
        DomainWorkerBlockReason::WorkerNotRunning => {
            WorkerBlockReason::WorkerNotRunning
        }
        DomainWorkerBlockReason::WorkerBusy => WorkerBlockReason::WorkerBusy,
        DomainWorkerBlockReason::UnknownMaster => {
            WorkerBlockReason::UnknownMaster
        }
        DomainWorkerBlockReason::MasterStillAlive => {
            WorkerBlockReason::MasterStillAlive
        }
        DomainWorkerBlockReason::MasterNotOlder => {
            WorkerBlockReason::MasterNotOlder
        }
        DomainWorkerBlockReason::IdentityChanged => {
            WorkerBlockReason::IdentityChanged
        }
    }
}

fn fleet_mode(value: DomainFleetMode) -> FleetMode {
    match value {
        DomainFleetMode::Running => FleetMode::Running,
        DomainFleetMode::ShuttingDown => FleetMode::ShuttingDown,
    }
}

fn process_identity(value: DomainProcessIdentity) -> ProcessIdentity {
    ProcessIdentity { pid: value.pid(), started_at: value.started_at() }
}

fn master_identity(value: DomainMasterIdentity) -> MasterIdentity {
    MasterIdentity {
        process: Some(process_identity(value.process())),
        generation: value.generation(),
    }
}

fn build_identity(value: DomainBuildIdentity) -> BuildIdentity {
    BuildIdentity {
        revision: value
            .revision()
            .map(|revision| format!("{revision:08x}"))
            .unwrap_or_default(),
        dirty: value.dirty(),
    }
}

fn resize_response(
    plan: claviron::supervisor::WorkerResizePlan
) -> ResizeWorkersResponse {
    ResizeWorkersResponse {
        accepted: true,
        previous_worker_count: u32::from(plan.previous_worker_count()),
        target_worker_count: u32::from(plan.target_worker_count()),
        submission_key: plan.command().raw(),
    }
}

fn timestamp(value: SystemTime) -> Result<Timestamp, Status> {
    let elapsed = value.duration_since(UNIX_EPOCH).map_err(|_| {
        Status::internal("worker timestamp precedes the Unix epoch")
    })?;
    Ok(Timestamp {
        seconds: i64::try_from(elapsed.as_secs()).map_err(|_| {
            Status::internal("worker timestamp exceeds protobuf range")
        })?,
        nanos: elapsed.subsec_nanos() as i32,
    })
}

fn duration(value: Duration) -> Result<ProtoDuration, Status> {
    Ok(ProtoDuration {
        seconds: i64::try_from(value.as_secs()).map_err(|_| {
            Status::internal("worker duration exceeds protobuf range")
        })?,
        nanos: value.subsec_nanos() as i32,
    })
}

fn manager_status(error: WorkerManagerError) -> Status {
    match error {
        WorkerManagerError::WorkerNotFound { .. } => {
            Status::not_found(error.to_string())
        }
        WorkerManagerError::CapacityReached { .. } => {
            Status::resource_exhausted(error.to_string())
        }
        WorkerManagerError::Unavailable
        | WorkerManagerError::LastRunningWorker { .. }
        | WorkerManagerError::WorkerNotRunning { .. }
        | WorkerManagerError::InsufficientRunningWorkers { .. }
        | WorkerManagerError::FleetNotStable { .. }
        | WorkerManagerError::FleetSizeMismatch { .. }
        | WorkerManagerError::LastConfiguredWorker
        | WorkerManagerError::ResizeNeedsRunningWorkers { .. } => {
            Status::failed_precondition(error.to_string())
        }
        WorkerManagerError::ShuttingDown => {
            Status::unavailable(error.to_string())
        }
        WorkerManagerError::Snapshot(_) => Status::internal(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use claviron::runtime::WorkerId;
    use claviron::supervisor::{
        BuildIdentity as DomainBuildIdentity, CommandKey,
        DrainReason as DomainDrainReason,
        ExitDisposition as DomainExitDisposition, FleetMode as DomainFleetMode,
        MasterIdentity as DomainMasterIdentity, OperationId,
        OperationKind as DomainOperationKind,
        OperationOrigin as DomainOperationOrigin,
        WorkerBlockReason as DomainWorkerBlockReason, WorkerIntent,
        WorkerListSnapshot, WorkerObservedPhase,
        WorkerOperation as DomainWorkerOperation,
        WorkerOwnership as DomainWorkerOwnership,
        WorkerStatus as DomainWorkerStatus,
    };
    use claviron::sys::process::ProcessIdentity as DomainProcessIdentity;

    use super::{snapshot_response, worker_status};
    use crate::proto::workers::worker_desired_state::State;
    use crate::proto::workers::worker_operation_origin::Origin;
    use crate::proto::workers::{
        FleetMode, WorkerBlockReason, WorkerDrainReason, WorkerExitDisposition,
        WorkerLifecycle, WorkerOperationKind, WorkerOwnership, WorkerPhase,
    };

    fn running(
        worker_id: u8,
        ownership: DomainWorkerOwnership,
    ) -> DomainWorkerStatus {
        DomainWorkerStatus {
            worker_id,
            ownership,
            process: Some(DomainProcessIdentity::new(
                6_000 + u32::from(worker_id),
                0x0a0b,
            )),
            uptime: Some(Duration::from_secs(90)),
            recovery_attempts: 0,
            incarnation: 3,
            reload_revision: 2,
            phase: WorkerObservedPhase::Running,
            phase_age: Duration::from_secs(80),
            desired: WorkerIntent::EnsureRunning,
            desired_age: Duration::from_secs(90),
            operation: None,
            heartbeat_age: Some(Duration::from_millis(700)),
            block_reason: None,
        }
    }

    #[test]
    fn worker_status_preserves_supervisor_ownership() {
        for (domain, wire) in [
            (DomainWorkerOwnership::Unowned, WorkerOwnership::Unowned),
            (DomainWorkerOwnership::Spawned, WorkerOwnership::Spawned),
            (DomainWorkerOwnership::Adopted, WorkerOwnership::Adopted),
        ] {
            let mapped =
                worker_status(running(1, domain)).expect("map worker status");
            assert_eq!(mapped.ownership, wire as i32);
        }
    }

    /// The label on the wire is the master's derivation, not a field a caller
    /// could set: a running process under a drain reads `stopping`.
    #[test]
    fn worker_status_carries_the_two_facts_and_the_label_derived_from_them() {
        let mut draining = running(1, DomainWorkerOwnership::Spawned);
        draining.phase = WorkerObservedPhase::DrainAcknowledged;
        draining.phase_age = Duration::from_secs(3);
        draining.desired = WorkerIntent::Drain {
            reason: DomainDrainReason::RollingRestart,
            after_exit: DomainExitDisposition::FinishFleetShutdown,
        };
        draining.desired_age = Duration::from_secs(12);
        draining.operation = Some(DomainWorkerOperation {
            id: OperationId::from_raw(9).unwrap(),
            kind: DomainOperationKind::Resize { from: 3, to: 4 },
            origin: DomainOperationOrigin::Management {
                via_worker: Some(WorkerId::new(2)),
                command: CommandKey::from_raw(0x0200_0197_0000_0001).unwrap(),
            },
            age: Duration::from_millis(250),
        });

        let mapped = worker_status(draining).expect("map worker status");

        assert_eq!(label(&mapped), WorkerLifecycle::Stopping);
        let process = mapped.process.expect("exact process");
        assert_eq!((process.pid, process.started_at), (6_001, 0x0a0b));
        assert_eq!(mapped.phase, WorkerPhase::DrainAcknowledged as i32);
        assert_eq!(mapped.phase_age.unwrap().seconds, 3);
        let desired = mapped.desired.expect("desired state");
        let Some(State::Drain(drain)) = desired.state else {
            panic!("a drain is the one desired case set: {desired:?}");
        };
        assert_eq!(drain.reason, WorkerDrainReason::RollingRestart as i32);
        assert_eq!(
            drain.after_exit,
            WorkerExitDisposition::FinishFleetShutdown as i32
        );
        assert_eq!(mapped.desired_age.unwrap().seconds, 12);
        let operation = mapped.operation.expect("operation");
        assert_eq!(operation.id, 9);
        assert_eq!(operation.kind, WorkerOperationKind::Resize as i32);
        assert_eq!((operation.resize_from, operation.resize_to), (3, 4));
        let origin = operation.origin.expect("origin");
        let Some(Origin::Management(management)) = origin.origin else {
            panic!("a management origin is the one case set: {origin:?}");
        };
        assert_eq!(management.via_worker, Some(2));
        assert_eq!(management.submission_key, 0x0200_0197_0000_0001);
        assert_eq!(operation.age.unwrap().nanos, 250_000_000);
        assert_eq!(mapped.heartbeat_age.unwrap().nanos, 700_000_000);
        assert_eq!(mapped.block_reason, WorkerBlockReason::Unspecified as i32);
    }

    fn label(mapped: &crate::proto::workers::WorkerStatus) -> WorkerLifecycle {
        WorkerLifecycle::try_from(mapped.lifecycle).unwrap()
    }

    /// A slot boot refused keeps the process that blocks it on the wire, with
    /// the reason, even though the master owns no handle to it.
    #[test]
    fn blocked_slot_names_its_process_and_reason() {
        let mut blocked = running(3, DomainWorkerOwnership::Unowned);
        blocked.process = Some(DomainProcessIdentity::new(31_337, 0x1213));
        blocked.incarnation = 5;
        blocked.phase = WorkerObservedPhase::ReconciliationBlocked;
        blocked.heartbeat_age = None;
        blocked.block_reason = Some(DomainWorkerBlockReason::MasterStillAlive);

        let mapped = worker_status(blocked).expect("map worker status");

        assert_eq!(label(&mapped), WorkerLifecycle::Unclaimed);
        assert_eq!(mapped.ownership, WorkerOwnership::Unowned as i32);
        assert_eq!(mapped.process.map(|process| process.pid), Some(31_337));
        assert_eq!(mapped.incarnation, 5);
        assert_eq!(mapped.phase, WorkerPhase::ReconciliationBlocked as i32);
        assert_eq!(
            mapped.block_reason,
            WorkerBlockReason::MasterStillAlive as i32
        );
        assert_eq!(mapped.heartbeat_age, None);
        assert_eq!(mapped.operation, None);
    }

    #[test]
    fn snapshot_header_carries_master_fleet_mode_and_build() {
        let build = DomainBuildIdentity::current();
        let snapshot = WorkerListSnapshot {
            captured_at: UNIX_EPOCH + Duration::from_secs(100),
            workers_expected: 1,
            build,
            master: Some(DomainMasterIdentity::new(
                DomainProcessIdentity::new(4_242, 0x0102),
                7,
            )),
            master_runtime: None,
            fleet_mode: DomainFleetMode::ShuttingDown,
            workers: vec![running(1, DomainWorkerOwnership::Spawned)],
        };

        let mapped = snapshot_response(snapshot).expect("map snapshot");

        let master = mapped.master.expect("master identity");
        let process = master.process.expect("master process");
        assert_eq!(
            (process.pid, process.started_at, master.generation),
            (4_242, 0x0102, 7)
        );
        assert_eq!(mapped.fleet_mode, FleetMode::ShuttingDown as i32);
        let wire_build = mapped.build.expect("build identity");
        assert_eq!(
            wire_build.revision,
            build
                .revision()
                .map(|revision| format!("{revision:08x}"))
                .unwrap_or_default()
        );
        assert_eq!(wire_build.dirty, build.dirty());
        assert_eq!(mapped.workers.len(), 1);
        assert_eq!(
            WorkerLifecycle::try_from(mapped.workers[0].lifecycle).unwrap(),
            WorkerLifecycle::Running
        );
    }
}
