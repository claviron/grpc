//! Fleet task management gRPC service.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use claviron::runtime::AppState;
use claviron::tasks::{
    Error as DomainTaskError, Reason as DomainTaskReason,
    TaskDispatch as DomainTaskDispatch,
    TaskExecutionOutcome as DomainTaskExecutionOutcome,
    TaskExecutionResult as DomainTaskExecutionResult,
    TaskKind as DomainTaskKind, TaskLifecycle as DomainTaskLifecycle,
    TaskListSnapshot, TaskManager as DomainTaskManager, TaskManagerError,
    TaskMember as DomainTaskMember, TaskMemberRole as DomainTaskMemberRole,
    TaskPlacementStatus as DomainTaskPlacementStatus,
    TaskScope as DomainTaskScope, TaskStatus as DomainTaskStatus,
    TaskStatusSnapshot, TaskTimingSummary as DomainTaskTiming,
};
use prost_types::{Duration as ProtoDuration, Timestamp};
use tonic::{Request, Response, Status};

use crate::proto::tasks::task_manager_server::{
    TaskManager, TaskManagerServer,
};
use crate::proto::tasks::{
    CronTiming, DaemonTiming, IntervalTiming, ListTasksRequest,
    ListTasksResponse, ManualTiming, RunTaskFailure, RunTaskFailureKind,
    RunTaskRequest, RunTaskResponse, RunTaskSuccess, TaskCommandRequest,
    TaskCommandResponse, TaskDispatch, TaskExecutionOutcome,
    TaskExecutionResult, TaskKind, TaskLifecycle, TaskMember, TaskMemberRole,
    TaskPlacementStatus, TaskScope, TaskStatus, TaskStatusRequest,
    TaskStatusResponse, TaskTiming, run_task_response, task_timing,
};

#[derive(Clone)]
pub struct TaskService {
    manager: DomainTaskManager,
}

impl TaskService {
    fn new(state: &AppState) -> Result<Self, Status> {
        Ok(Self {
            manager: DomainTaskManager::new(state).map_err(manager_status)?,
        })
    }

    fn command(
        &self,
        request: Request<TaskCommandRequest>,
        apply: impl FnOnce(&DomainTaskManager, &str) -> Result<(), TaskManagerError>,
    ) -> Result<Response<TaskCommandResponse>, Status> {
        let name = request.into_inner().name;
        apply(&self.manager, &name).map_err(manager_status)?;
        Ok(Response::new(TaskCommandResponse { name, accepted: true }))
    }
}

#[tonic::async_trait]
impl TaskManager for TaskService {
    async fn list_tasks(
        &self,
        _request: Request<ListTasksRequest>,
    ) -> Result<Response<ListTasksResponse>, Status> {
        Ok(Response::new(snapshot_response(
            self.manager.list().map_err(manager_status)?,
        )?))
    }

    async fn get_task_status(
        &self,
        request: Request<TaskStatusRequest>,
    ) -> Result<Response<TaskStatusResponse>, Status> {
        let name = request.into_inner().name;
        Ok(Response::new(status_response(
            self.manager.status(&name).map_err(manager_status)?,
        )?))
    }

    async fn start_task(
        &self,
        request: Request<TaskCommandRequest>,
    ) -> Result<Response<TaskCommandResponse>, Status> {
        self.command(request, DomainTaskManager::start)
    }

    async fn stop_task(
        &self,
        request: Request<TaskCommandRequest>,
    ) -> Result<Response<TaskCommandResponse>, Status> {
        self.command(request, DomainTaskManager::stop)
    }

    async fn reload_task(
        &self,
        request: Request<TaskCommandRequest>,
    ) -> Result<Response<TaskCommandResponse>, Status> {
        self.command(request, DomainTaskManager::reload)
    }

    async fn restart_task(
        &self,
        request: Request<TaskCommandRequest>,
    ) -> Result<Response<TaskCommandResponse>, Status> {
        self.command(request, DomainTaskManager::restart)
    }

    async fn run_task(
        &self,
        request: Request<RunTaskRequest>,
    ) -> Result<Response<RunTaskResponse>, Status> {
        let request = request.into_inner();
        let name = request.name;
        let execution_timeout = request
            .execution_timeout
            .map(parse_execution_timeout)
            .transpose()?;
        let outcome = self
            .manager
            .run(&name, execution_timeout)
            .await
            .map_err(manager_status)?;
        let result = match outcome.result {
            Ok(()) => run_task_response::Result::Success(RunTaskSuccess {}),
            Err(error) => {
                run_task_response::Result::Failure(task_failure(error))
            }
        };
        Ok(Response::new(RunTaskResponse {
            name,
            run_id: outcome.run_id.raw(),
            result: Some(result),
        }))
    }
}

pub fn create_task_service(
    state: AppState
) -> Result<TaskManagerServer<TaskService>, Status> {
    Ok(TaskManagerServer::new(TaskService::new(&state)?))
}

fn snapshot_response(
    snapshot: TaskListSnapshot
) -> Result<ListTasksResponse, Status> {
    Ok(ListTasksResponse {
        captured_at: Some(timestamp(snapshot.captured_at)?),
        members_expected: u32::from(snapshot.members_expected),
        members_reporting: u32::from(snapshot.members_reporting),
        tasks: snapshot
            .tasks
            .into_iter()
            .map(task_status)
            .collect::<Result<_, _>>()?,
    })
}

fn status_response(
    snapshot: TaskStatusSnapshot
) -> Result<TaskStatusResponse, Status> {
    Ok(TaskStatusResponse {
        captured_at: Some(timestamp(snapshot.captured_at)?),
        members_expected: u32::from(snapshot.members_expected),
        members_reporting: u32::from(snapshot.members_reporting),
        task: Some(task_status(snapshot.task)?),
    })
}

fn task_status(task: DomainTaskStatus) -> Result<TaskStatus, Status> {
    Ok(TaskStatus {
        name: task.name,
        kind: match task.kind {
            DomainTaskKind::Builtin => TaskKind::Builtin,
            DomainTaskKind::Command => TaskKind::Command,
            DomainTaskKind::Php => TaskKind::Php,
            DomainTaskKind::Js => TaskKind::Js,
            DomainTaskKind::Lua => TaskKind::Lua,
        } as i32,
        scope: match task.scope {
            DomainTaskScope::Master => TaskScope::Master,
            DomainTaskScope::Workers => TaskScope::Workers,
            DomainTaskScope::Fleet => TaskScope::Fleet,
        } as i32,
        dispatch: match task.dispatch {
            DomainTaskDispatch::Each => TaskDispatch::Each,
            DomainTaskDispatch::One => TaskDispatch::One,
            DomainTaskDispatch::Pool => TaskDispatch::Pool,
        } as i32,
        timing: Some(task_timing(task.timing)?),
        concurrency: u32::from(task.concurrency),
        placements: task
            .placements
            .into_iter()
            .map(task_placement)
            .collect::<Result<_, _>>()?,
    })
}

fn task_timing(timing: DomainTaskTiming) -> Result<TaskTiming, Status> {
    let schedule = match timing {
        DomainTaskTiming::Manual { execution_timeout } => {
            task_timing::Schedule::Manual(ManualTiming {
                execution_timeout: Some(duration(execution_timeout)?),
            })
        }
        DomainTaskTiming::Daemon { enabled } => {
            task_timing::Schedule::Daemon(DaemonTiming { enabled })
        }
        DomainTaskTiming::Interval { enabled, every, execution_timeout } => {
            task_timing::Schedule::Interval(IntervalTiming {
                every: Some(duration(every)?),
                execution_timeout: Some(duration(execution_timeout)?),
                enabled,
            })
        }
        DomainTaskTiming::Cron { enabled, expression, execution_timeout } => {
            task_timing::Schedule::Cron(CronTiming {
                expression,
                execution_timeout: Some(duration(execution_timeout)?),
                enabled,
            })
        }
    };
    Ok(TaskTiming { schedule: Some(schedule) })
}

fn task_placement(
    placement: DomainTaskPlacementStatus
) -> Result<TaskPlacementStatus, Status> {
    Ok(TaskPlacementStatus {
        member: Some(task_member(placement.member)),
        lifecycle: match placement.lifecycle {
            DomainTaskLifecycle::Ineligible => TaskLifecycle::Ineligible,
            DomainTaskLifecycle::Disabled => TaskLifecycle::Disabled,
            DomainTaskLifecycle::Inactive => TaskLifecycle::Inactive,
            DomainTaskLifecycle::Active => TaskLifecycle::Active,
            DomainTaskLifecycle::Stopping => TaskLifecycle::Stopping,
            DomainTaskLifecycle::Finished => TaskLifecycle::Finished,
            DomainTaskLifecycle::MissingRunner => TaskLifecycle::MissingRunner,
        } as i32,
        generation: placement.generation,
        in_flight: u64::try_from(placement.in_flight).map_err(|_| {
            Status::internal("task in-flight count exceeds uint64")
        })?,
        owned_slots: u64::try_from(placement.owned_slots).map_err(|_| {
            Status::internal("task owned-slot count exceeds uint64")
        })?,
        last_execution: placement
            .last_execution
            .map(task_execution)
            .transpose()?,
        observed_at: Some(timestamp(placement.observed_at)?),
    })
}

fn task_member(member: DomainTaskMember) -> TaskMember {
    TaskMember {
        node_id: u32::from(member.node_id),
        role: match member.role {
            DomainTaskMemberRole::Master => TaskMemberRole::Master,
            DomainTaskMemberRole::Worker => TaskMemberRole::Worker,
            DomainTaskMemberRole::Standalone => TaskMemberRole::Standalone,
        } as i32,
    }
}

fn task_execution(
    outcome: DomainTaskExecutionOutcome
) -> Result<TaskExecutionOutcome, Status> {
    Ok(TaskExecutionOutcome {
        result: match outcome.result {
            DomainTaskExecutionResult::Succeeded => {
                TaskExecutionResult::Succeeded
            }
            DomainTaskExecutionResult::Failed => TaskExecutionResult::Failed,
            DomainTaskExecutionResult::Cancelled => {
                TaskExecutionResult::Cancelled
            }
            DomainTaskExecutionResult::TimedOut => {
                TaskExecutionResult::TimedOut
            }
            DomainTaskExecutionResult::GaveUp => TaskExecutionResult::GaveUp,
        } as i32,
        finished_at: Some(timestamp(outcome.finished_at)?),
    })
}

fn timestamp(value: SystemTime) -> Result<Timestamp, Status> {
    let elapsed = value.duration_since(UNIX_EPOCH).map_err(|_| {
        Status::internal("task timestamp precedes the Unix epoch")
    })?;
    Ok(Timestamp {
        seconds: i64::try_from(elapsed.as_secs()).map_err(|_| {
            Status::internal("task timestamp exceeds protobuf range")
        })?,
        nanos: elapsed.subsec_nanos() as i32,
    })
}

fn duration(value: Duration) -> Result<ProtoDuration, Status> {
    Ok(ProtoDuration {
        seconds: i64::try_from(value.as_secs()).map_err(|_| {
            Status::internal("task interval exceeds protobuf range")
        })?,
        nanos: value.subsec_nanos() as i32,
    })
}

fn parse_execution_timeout(value: ProtoDuration) -> Result<Duration, Status> {
    if value.seconds < 0 || value.nanos < 0 || value.nanos >= 1_000_000_000 {
        return Err(Status::invalid_argument(
            "execution_timeout must be a positive protobuf duration",
        ));
    }
    let timeout = Duration::new(value.seconds as u64, value.nanos as u32);
    if timeout.is_zero()
        || std::time::Instant::now().checked_add(timeout).is_none()
    {
        return Err(Status::invalid_argument(
            "execution_timeout must be greater than zero and representable by the runtime",
        ));
    }
    Ok(timeout)
}

fn task_failure(error: DomainTaskError) -> RunTaskFailure {
    let message = error.to_string();
    let kind = match error {
        DomainTaskError::Io(_) => RunTaskFailureKind::Io,
        DomainTaskError::Exit(reason) => match reason {
            DomainTaskReason::Cancelled => RunTaskFailureKind::Cancelled,
            DomainTaskReason::Shutdown => RunTaskFailureKind::Shutdown,
            DomainTaskReason::GracefulTimeout => {
                RunTaskFailureKind::GracefulTimeout
            }
            DomainTaskReason::ExecutionTimeout => {
                RunTaskFailureKind::ExecutionTimeout
            }
            DomainTaskReason::Custom(_) => RunTaskFailureKind::Task,
        },
        DomainTaskError::Other(_) => RunTaskFailureKind::Task,
    };
    RunTaskFailure { kind: kind as i32, message }
}

fn manager_status(error: TaskManagerError) -> Status {
    match error {
        TaskManagerError::EmptyTaskName
        | TaskManagerError::TaskNameTooLong { .. }
        | TaskManagerError::InvalidExecutionTimeout => {
            Status::invalid_argument(error.to_string())
        }
        TaskManagerError::TaskNotFound(_) => {
            Status::not_found(error.to_string())
        }
        TaskManagerError::TaskStopped(_)
        | TaskManagerError::RestartRequiresDaemon(_)
        | TaskManagerError::ManualTaskHasNoSchedule(_)
        | TaskManagerError::TaskIneligible(_)
        | TaskManagerError::TaskRunnerUnavailable(_)
        | TaskManagerError::DaemonRequiresStart(_)
        | TaskManagerError::ServiceUnavailable
        | TaskManagerError::FleetUnavailable => {
            Status::failed_precondition(error.to_string())
        }
        TaskManagerError::ShuttingDown => {
            Status::unavailable(error.to_string())
        }
        TaskManagerError::Snapshot(_) => Status::internal(error.to_string()),
    }
}
