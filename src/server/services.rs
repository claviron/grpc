//! Fleet runnable-service management gRPC service.

use std::time::{SystemTime, UNIX_EPOCH};

use claviron::http::ListenerId;
use claviron::orbit::placement::Dispatch;
use claviron::orbit::service::{
    FleetMember as DomainServiceMember,
    FleetMemberRole as DomainServiceMemberRole, FleetServiceListSnapshot,
    FleetServiceManager as DomainServiceManager, FleetServiceManagerError,
    FleetServicePlacement as DomainServicePlacement,
    FleetServiceStatus as DomainServiceStatus, FleetServiceStatusSnapshot,
};
use claviron::runtime::{
    AppState, ServiceManagerError,
    ServiceStartPolicy as DomainServiceStartPolicy,
    ServiceStatus as DomainServiceLifecycle,
};
use prost_types::Timestamp;
use tonic::{Request, Response, Status};

use crate::proto::services::service_manager_server::{
    ServiceManager, ServiceManagerServer,
};
use crate::proto::services::{
    ListServicesRequest, ListServicesResponse, ServiceCommandRequest,
    ServiceCommandResponse, ServiceDispatch, ServiceLifecycle, ServiceMember,
    ServiceMemberRole, ServicePlacement, ServiceStartPolicy, ServiceStatus,
    ServiceStatusRequest, ServiceStatusResponse,
};

#[derive(Clone)]
pub struct ServiceManagerService {
    manager: DomainServiceManager,
}

/// Trusted adapter extension naming the runnable carrying this RPC.
#[derive(Clone)]
pub(crate) struct ManagementTransport(pub(crate) ListenerId);

impl ManagementTransport {
    fn owns(
        &self,
        name: &str,
    ) -> bool {
        name.strip_prefix("Listener:") == Some(self.0.as_str())
    }
}

fn command_transport<'a>(
    owner: Option<&'a ManagementTransport>,
    name: &str,
    action: ServiceAction,
) -> Result<Option<&'a ManagementTransport>, Status> {
    if matches!(action, ServiceAction::Stop | ServiceAction::Restart) {
        let owner = owner.ok_or_else(|| {
            Status::failed_precondition(
                "management transport ownership is missing",
            )
        })?;
        if owner.owns(name) {
            return Err(Status::failed_precondition(format!(
                "cannot stop or restart service '{name}' carrying this management connection; connect through another ingress"
            )));
        }
    }
    Ok(owner)
}

impl ServiceManagerService {
    fn new(state: &AppState) -> Result<Self, Status> {
        Ok(Self {
            manager: DomainServiceManager::new(state)
                .map_err(manager_status)?,
        })
    }

    async fn command(
        &self,
        request: Request<ServiceCommandRequest>,
        action: ServiceAction,
    ) -> Result<Response<ServiceCommandResponse>, Status> {
        let owner = command_transport(
            request.extensions().get::<ManagementTransport>(),
            &request.get_ref().name,
            action,
        )?;
        tracing::debug!(
            service = %request.get_ref().name,
            listener = owner.map(|owner| owner.0.as_str()),
            serving_transport = owner.is_some_and(|owner| owner.owns(&request.get_ref().name)),
            ?action,
            "submitting management service command"
        );
        let name = request.into_inner().name;
        match action {
            ServiceAction::Start => self.manager.start(&name).await,
            ServiceAction::Stop => self.manager.stop(&name).await,
            ServiceAction::Reload => self.manager.reload(&name).await,
            ServiceAction::Restart => self.manager.restart(&name).await,
        }
        .map_err(manager_status)?;
        Ok(Response::new(ServiceCommandResponse { name, accepted: true }))
    }
}

#[derive(Clone, Copy, Debug)]
enum ServiceAction {
    Start,
    Stop,
    Reload,
    Restart,
}

#[cfg(test)]
#[path = "../../tests/transport_guard.rs"]
mod transport_tests;

#[tonic::async_trait]
impl ServiceManager for ServiceManagerService {
    async fn list_services(
        &self,
        _request: Request<ListServicesRequest>,
    ) -> Result<Response<ListServicesResponse>, Status> {
        let snapshot = self.manager.list().await.map_err(manager_status)?;
        Ok(Response::new(snapshot_response(snapshot)?))
    }

    async fn get_service_status(
        &self,
        request: Request<ServiceStatusRequest>,
    ) -> Result<Response<ServiceStatusResponse>, Status> {
        let name = request.into_inner().name;
        let snapshot =
            self.manager.status(&name).await.map_err(manager_status)?;
        Ok(Response::new(status_response(snapshot)?))
    }

    async fn start_service(
        &self,
        request: Request<ServiceCommandRequest>,
    ) -> Result<Response<ServiceCommandResponse>, Status> {
        self.command(request, ServiceAction::Start).await
    }

    async fn stop_service(
        &self,
        request: Request<ServiceCommandRequest>,
    ) -> Result<Response<ServiceCommandResponse>, Status> {
        self.command(request, ServiceAction::Stop).await
    }

    async fn reload_service(
        &self,
        request: Request<ServiceCommandRequest>,
    ) -> Result<Response<ServiceCommandResponse>, Status> {
        self.command(request, ServiceAction::Reload).await
    }

    async fn restart_service(
        &self,
        request: Request<ServiceCommandRequest>,
    ) -> Result<Response<ServiceCommandResponse>, Status> {
        self.command(request, ServiceAction::Restart).await
    }
}

pub fn create_service_manager(
    state: AppState
) -> Result<ServiceManagerServer<ServiceManagerService>, Status> {
    Ok(ServiceManagerServer::new(ServiceManagerService::new(&state)?))
}

fn snapshot_response(
    snapshot: FleetServiceListSnapshot
) -> Result<ListServicesResponse, Status> {
    Ok(ListServicesResponse {
        captured_at: Some(timestamp(snapshot.captured_at)?),
        members_expected: u32::from(snapshot.members_expected),
        members_reporting: u32::from(snapshot.members_reporting),
        services: snapshot
            .services
            .into_iter()
            .map(service_status)
            .collect::<Result<_, _>>()?,
    })
}

fn status_response(
    snapshot: FleetServiceStatusSnapshot
) -> Result<ServiceStatusResponse, Status> {
    Ok(ServiceStatusResponse {
        captured_at: Some(timestamp(snapshot.captured_at)?),
        members_expected: u32::from(snapshot.members_expected),
        members_reporting: u32::from(snapshot.members_reporting),
        service: Some(service_status(snapshot.service)?),
    })
}

fn service_status(
    service: DomainServiceStatus
) -> Result<ServiceStatus, Status> {
    Ok(ServiceStatus {
        name: service.name,
        placements: service
            .placements
            .into_iter()
            .map(service_placement)
            .collect::<Result<_, _>>()?,
    })
}

fn service_placement(
    placement: DomainServicePlacement
) -> Result<ServicePlacement, Status> {
    Ok(ServicePlacement {
        active_executions: Some(placement.active_executions),
        dispatch: match placement.dispatch {
            Dispatch::Each => ServiceDispatch::Each,
            Dispatch::One => ServiceDispatch::One,
            Dispatch::Pool => ServiceDispatch::Pool,
        } as i32,
        member: Some(service_member(placement.member)),
        lifecycle: match placement.status {
            DomainServiceLifecycle::Running => ServiceLifecycle::Running,
            DomainServiceLifecycle::Stopping => ServiceLifecycle::Stopping,
            DomainServiceLifecycle::Stopped => ServiceLifecycle::Stopped,
            DomainServiceLifecycle::Failed => ServiceLifecycle::Failed,
        } as i32,
        reloadable: placement.reloadable,
        generation: placement.generation,
        reload_revision: placement.reload_revision,
        last_error: placement.last_error,
        last_error_truncated: placement.last_error_truncated,
        last_reload_error: placement.last_reload_error,
        last_reload_error_truncated: placement.last_reload_error_truncated,
        observed_at: Some(timestamp(placement.observed_at)?),
        start_policy: match placement.start_policy {
            DomainServiceStartPolicy::Automatic => {
                ServiceStartPolicy::Automatic
            }
            DomainServiceStartPolicy::Manual => ServiceStartPolicy::Manual,
            DomainServiceStartPolicy::Unavailable => {
                ServiceStartPolicy::Unavailable
            }
        } as i32,
    })
}

fn service_member(member: DomainServiceMember) -> ServiceMember {
    ServiceMember {
        node_id: u32::from(member.node_id),
        role: match member.role {
            DomainServiceMemberRole::Master => ServiceMemberRole::Master,
            DomainServiceMemberRole::Worker => ServiceMemberRole::Worker,
            DomainServiceMemberRole::Standalone => {
                ServiceMemberRole::Standalone
            }
        } as i32,
    }
}

fn timestamp(value: SystemTime) -> Result<Timestamp, Status> {
    let elapsed = value.duration_since(UNIX_EPOCH).map_err(|_| {
        Status::internal("service timestamp precedes the Unix epoch")
    })?;
    Ok(Timestamp {
        seconds: i64::try_from(elapsed.as_secs()).map_err(|_| {
            Status::internal("service timestamp exceeds protobuf range")
        })?,
        nanos: elapsed.subsec_nanos() as i32,
    })
}

fn manager_status(error: FleetServiceManagerError) -> Status {
    match error {
        FleetServiceManagerError::EmptyServiceName
        | FleetServiceManagerError::ServiceNameTooLong { .. } => {
            Status::invalid_argument(error.to_string())
        }
        FleetServiceManagerError::ServiceNotFound(_) => {
            Status::not_found(error.to_string())
        }
        FleetServiceManagerError::ShuttingDown => {
            Status::unavailable(error.to_string())
        }
        FleetServiceManagerError::ServiceNotReloadable(_)
        | FleetServiceManagerError::ServiceUnavailable(_)
        | FleetServiceManagerError::ContinuityProtected { .. }
        | FleetServiceManagerError::LocalManagerUnavailable
        | FleetServiceManagerError::ControlUnavailable
        | FleetServiceManagerError::FleetUnavailable
        | FleetServiceManagerError::SnapshotPublisherUnavailable => {
            Status::failed_precondition(error.to_string())
        }
        FleetServiceManagerError::Snapshot(_) => {
            Status::internal(error.to_string())
        }
        FleetServiceManagerError::Local(local) => local_manager_status(local),
    }
}

fn local_manager_status(error: ServiceManagerError) -> Status {
    match error {
        ServiceManagerError::NotFound(_) => {
            Status::not_found(error.to_string())
        }
        ServiceManagerError::RuntimeUnavailable
        | ServiceManagerError::ShuttingDown => {
            Status::unavailable(error.to_string())
        }
        ServiceManagerError::NotReloadable(_)
        | ServiceManagerError::Unavailable(_)
        | ServiceManagerError::Busy { .. } => {
            Status::failed_precondition(error.to_string())
        }
        ServiceManagerError::OperationFailed { .. } => {
            Status::internal(error.to_string())
        }
        // `ServiceManagerError` is `#[non_exhaustive]`, so a variant added
        // upstream reaches this arm instead of failing this build. `internal`
        // is the honest default: we do not know whether the caller could have
        // avoided it, and saying so is better than guessing a status the
        // client will act on.
        _ => Status::internal(error.to_string()),
    }
}
