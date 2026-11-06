//! Runtime-neutral application fleet management.

use std::time::{SystemTime, UNIX_EPOCH};

use claviron::app::fleet::{
    FleetApplicationManager, FleetApplicationManagerError,
    FleetApplicationPlacement, FleetApplicationStatus,
};
use claviron::app::{
    ApplicationId as DomainApplicationId,
    ApplicationLifecycle as DomainApplicationLifecycle, ApplicationName,
    ApplicationRuntime,
};
use claviron::orbit::service::{
    FleetMember as DomainFleetMember, FleetMemberRole as DomainMemberRole,
};
use claviron::runtime::AppState;
use prost_types::Timestamp;
use tonic::{Request, Response, Status};

use crate::proto::applications::application_manager_server::{
    ApplicationManager, ApplicationManagerServer,
};
use crate::proto::applications::{
    ApplicationCommandRequest, ApplicationCommandResponse,
    ApplicationDescription, ApplicationId, ApplicationLifecycle,
    ApplicationPlacement, ApplicationPoolStatus, ApplicationStatus,
    ApplicationStatusRequest, ApplicationStatusResponse, FleetMember,
    FleetMemberRole, ListApplicationsRequest, ListApplicationsResponse,
};

#[derive(Clone)]
pub struct ApplicationManagerService {
    manager: FleetApplicationManager,
}

#[tonic::async_trait]
impl ApplicationManager for ApplicationManagerService {
    async fn list_applications(
        &self,
        _request: Request<ListApplicationsRequest>,
    ) -> Result<Response<ListApplicationsResponse>, Status> {
        let snapshot = self.manager.list().map_err(manager_status)?;
        let applications = snapshot
            .applications
            .into_iter()
            .map(application_status)
            .collect::<Result<_, _>>()?;
        Ok(Response::new(ListApplicationsResponse {
            captured_at: Some(timestamp(snapshot.captured_at)?),
            members_expected: u32::from(snapshot.members_expected),
            members_reporting: u32::from(snapshot.members_reporting),
            applications,
        }))
    }

    async fn get_application_status(
        &self,
        request: Request<ApplicationStatusRequest>,
    ) -> Result<Response<ApplicationStatusResponse>, Status> {
        let id = application_id(request.into_inner().id)?;
        let snapshot = self.manager.status(&id).map_err(manager_status)?;
        Ok(Response::new(ApplicationStatusResponse {
            captured_at: Some(timestamp(snapshot.captured_at)?),
            members_expected: u32::from(snapshot.members_expected),
            members_reporting: u32::from(snapshot.members_reporting),
            application: Some(application_status(snapshot.application)?),
        }))
    }

    async fn start_application(
        &self,
        request: Request<ApplicationCommandRequest>,
    ) -> Result<Response<ApplicationCommandResponse>, Status> {
        self.command(request.into_inner().id, |manager, id| manager.start(id))
    }

    async fn stop_application(
        &self,
        request: Request<ApplicationCommandRequest>,
    ) -> Result<Response<ApplicationCommandResponse>, Status> {
        self.command(request.into_inner().id, |manager, id| manager.stop(id))
    }

    async fn restart_application(
        &self,
        request: Request<ApplicationCommandRequest>,
    ) -> Result<Response<ApplicationCommandResponse>, Status> {
        self.command(request.into_inner().id, |manager, id| manager.restart(id))
    }
}

impl ApplicationManagerService {
    fn command(
        &self,
        id: Option<ApplicationId>,
        apply: impl FnOnce(
            &FleetApplicationManager,
            &DomainApplicationId,
        ) -> Result<(), FleetApplicationManagerError>,
    ) -> Result<Response<ApplicationCommandResponse>, Status> {
        let id = application_id(id)?;
        apply(&self.manager, &id).map_err(manager_status)?;
        Ok(Response::new(ApplicationCommandResponse {
            id: Some(proto_id(&id)),
            accepted: true,
        }))
    }
}

pub fn create_application_manager(
    state: AppState
) -> Result<ApplicationManagerServer<ApplicationManagerService>, Status> {
    let manager =
        FleetApplicationManager::new(&state).map_err(manager_status)?;
    Ok(ApplicationManagerServer::new(ApplicationManagerService { manager }))
}

fn application_id(
    value: Option<ApplicationId>
) -> Result<DomainApplicationId, Status> {
    let value = value.ok_or_else(|| {
        Status::invalid_argument("application id is required")
    })?;
    let runtime = ApplicationRuntime::new(value.runtime)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    let name = ApplicationName::new(value.name)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    Ok(DomainApplicationId::new(runtime, name))
}

pub(super) fn application_status(
    value: FleetApplicationStatus
) -> Result<ApplicationStatus, Status> {
    Ok(ApplicationStatus {
        id: Some(proto_id(&value.id)),
        placements: value
            .placements
            .into_iter()
            .map(application_placement)
            .collect::<Result<_, _>>()?,
    })
}

fn application_placement(
    value: FleetApplicationPlacement
) -> Result<ApplicationPlacement, Status> {
    Ok(ApplicationPlacement {
        description: Some(ApplicationDescription {
            runtime: value.description.runtime,
            frameworks: value.description.frameworks,
            icon: value.description.icon,
            runner: value.description.runner,
            request_mode: value.description.request_mode,
        }),
        member: Some(member(value.member)),
        lifecycle: match value.lifecycle {
            DomainApplicationLifecycle::Starting => {
                ApplicationLifecycle::Starting
            }
            DomainApplicationLifecycle::Running => {
                ApplicationLifecycle::Running
            }
            DomainApplicationLifecycle::Stopping => {
                ApplicationLifecycle::Stopping
            }
            DomainApplicationLifecycle::Stopped => {
                ApplicationLifecycle::Stopped
            }
            DomainApplicationLifecycle::Failed => ApplicationLifecycle::Failed,
        } as i32,
        enabled: value.enabled,
        generation: value.generation,
        pool: value.pool.map(|pool| ApplicationPoolStatus {
            accepting: pool.accepting,
            instances: pool.instances,
            ready: pool.ready,
            busy: pool.busy,
            retiring: pool.retiring,
            backing_off: pool.backing_off,
            exhausted: pool.exhausted,
        }),
        last_error: value.last_error,
        last_error_truncated: value.last_error_truncated,
        observed_at: Some(timestamp(value.observed_at)?),
    })
}

fn proto_id(value: &DomainApplicationId) -> ApplicationId {
    ApplicationId {
        runtime: value.runtime().as_str().to_owned(),
        name: value.name().as_str().to_owned(),
    }
}

fn member(value: DomainFleetMember) -> FleetMember {
    FleetMember {
        node_id: u32::from(value.node_id),
        role: match value.role {
            DomainMemberRole::Master => FleetMemberRole::Master,
            DomainMemberRole::Worker => FleetMemberRole::Worker,
            DomainMemberRole::Standalone => FleetMemberRole::Standalone,
        } as i32,
    }
}

fn timestamp(value: SystemTime) -> Result<Timestamp, Status> {
    let elapsed = value.duration_since(UNIX_EPOCH).map_err(|_| {
        Status::internal("application timestamp precedes the Unix epoch")
    })?;
    Ok(Timestamp {
        seconds: i64::try_from(elapsed.as_secs()).map_err(|_| {
            Status::internal("application timestamp exceeds protobuf range")
        })?,
        nanos: elapsed.subsec_nanos() as i32,
    })
}

fn manager_status(error: FleetApplicationManagerError) -> Status {
    match error {
        FleetApplicationManagerError::ApplicationNotFound(_) => {
            Status::not_found(error.to_string())
        }
        FleetApplicationManagerError::Command(_) => {
            Status::invalid_argument(error.to_string())
        }
        FleetApplicationManagerError::LocalManagerUnavailable
        | FleetApplicationManagerError::ControlUnavailable
        | FleetApplicationManagerError::MembershipUnavailable
        | FleetApplicationManagerError::SnapshotPublisherUnavailable => {
            Status::failed_precondition(error.to_string())
        }
        FleetApplicationManagerError::SnapshotIncomplete { .. }
        | FleetApplicationManagerError::ShuttingDown
        | FleetApplicationManagerError::FleetUnavailable
        | FleetApplicationManagerError::Snapshot(_) => {
            Status::unavailable(error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use claviron::app::ApplicationPoolStatus as DomainPoolStatus;

    use super::*;

    #[test]
    fn application_identity_requires_both_runtime_and_name() {
        assert_eq!(
            application_id(None).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            application_id(Some(ApplicationId {
                runtime: " ".into(),
                name: "web".into()
            }))
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn placement_preserves_unknown_pool_counters() {
        let placement = FleetApplicationPlacement {
            description: claviron::app::ApplicationDescription::new(
                "javascript",
                "fetch",
            )
            .framework("example-framework")
            .runner("example-runner"),
            member: DomainFleetMember {
                node_id: 2,
                role: DomainMemberRole::Worker,
            },
            lifecycle: DomainApplicationLifecycle::Running,
            enabled: true,
            generation: 3,
            pool: Some(DomainPoolStatus {
                accepting: None,
                instances: 1,
                ready: None,
                busy: Some(1),
                retiring: None,
                backing_off: None,
                exhausted: None,
            }),
            last_error: None,
            last_error_truncated: false,
            observed_at: UNIX_EPOCH,
        };

        let encoded = application_placement(placement).unwrap();
        assert_eq!(
            encoded.description.as_ref().unwrap().request_mode.as_deref(),
            Some("fetch")
        );
        let pool = encoded.pool.unwrap();
        assert_eq!(pool.accepting, None);
        assert_eq!(pool.ready, None);
        assert_eq!(pool.busy, Some(1));
    }
}
