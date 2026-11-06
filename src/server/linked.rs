//! gRPC view of the live Orbit Link directory and command inbox.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use claviron::app::fleet::{
    FleetApplicationPlacement, FleetApplicationStatus,
    decode_link_snapshot_rows,
};
use claviron::app::{ApplicationName, ApplicationRuntime};
use claviron::edge::VhostResolver;
use claviron::orbit::link::application::{
    ApplicationService, ControlTarget, Error as LinkError,
    LinkedApplication as LinkApplication,
};
use claviron::runtime::{AppState, FleetName};
use prost_types::Timestamp;
use tonic::{Request, Response, Status};

use super::applications::application_status;
use crate::proto::applications::ListApplicationsResponse;
use crate::proto::linked_applications::linked_application_manager_server::{
    LinkedApplicationManager, LinkedApplicationManagerServer,
};
use crate::proto::linked_applications::{
    LinkReachability, LinkedApplicationCommandRequest,
    LinkedApplicationCommandResponse, LinkedApplicationId,
    LinkedApplicationInfo, LinkedApplicationLane, LinkedApplicationStatus,
    LinkedApplicationStatusRequest, LinkedApplicationStatusResponse,
    ListLinkedApplicationsRequest, ListLinkedApplicationsResponse,
};

#[derive(Clone)]
pub struct LinkedApplicationManagerService {
    state: AppState,
}

impl LinkedApplicationManagerService {
    fn applications(&self) -> Result<Arc<ApplicationService>, Status> {
        let applications = self
            .state
            .registry_ref()
            .resolve::<ApplicationService>()
            .ok_or_else(|| {
                Status::failed_precondition(
                    "Orbit application link is not registered",
                )
            })?;
        if let Some(vhosts) =
            self.state.registry_ref().resolve::<VhostResolver>()
        {
            for (_, record) in vhosts.snapshot().canonical_entries() {
                for route in record.config.orbit() {
                    applications
                        .track_target(route.fleet_name, &route.application);
                }
            }
        }
        Ok(applications)
    }

    fn command(
        &self,
        request: LinkedApplicationCommandRequest,
        name: &str,
        target_required: bool,
    ) -> Result<Response<LinkedApplicationCommandResponse>, Status> {
        let (fleet, link_name) = domain_id(request.id)?;
        let application = request
            .application
            .map(|id| {
                ApplicationRuntime::new(id.runtime.clone()).map_err(
                    |error| Status::invalid_argument(error.to_string()),
                )?;
                ApplicationName::new(id.name.clone()).map_err(|error| {
                    Status::invalid_argument(error.to_string())
                })?;
                Ok::<_, Status>(id)
            })
            .transpose()?;
        if target_required && application.is_none() {
            return Err(Status::invalid_argument(
                "hosted application id is required",
            ));
        }
        let target = application.as_ref().map(|id| ControlTarget {
            runtime: id.runtime.clone(),
            name: id.name.clone(),
        });
        self.applications()?
            .forward_command(fleet, &link_name, name, request.payload, target)
            .map_err(link_status)?;
        Ok(Response::new(LinkedApplicationCommandResponse {
            id: Some(LinkedApplicationId {
                fleet_name: fleet.to_string(),
                name: link_name,
                transport: "orbit".to_owned(),
            }),
            accepted: true,
            application,
        }))
    }
}

#[tonic::async_trait]
impl LinkedApplicationManager for LinkedApplicationManagerService {
    async fn list_linked_applications(
        &self,
        _request: Request<ListLinkedApplicationsRequest>,
    ) -> Result<Response<ListLinkedApplicationsResponse>, Status> {
        let applications =
            self.applications()?.linked_applications().map_err(link_status)?;
        Ok(Response::new(ListLinkedApplicationsResponse {
            captured_at: Some(timestamp(SystemTime::now())?),
            applications: applications
                .into_iter()
                .map(proto_status)
                .collect::<Result<_, _>>()?,
        }))
    }

    async fn get_linked_application_status(
        &self,
        request: Request<LinkedApplicationStatusRequest>,
    ) -> Result<Response<LinkedApplicationStatusResponse>, Status> {
        let (fleet, name) = domain_id(request.into_inner().id)?;
        let application = self
            .applications()?
            .linked_applications()
            .map_err(link_status)?
            .into_iter()
            .find(|entry| entry.fleet == fleet && entry.name == name)
            .ok_or_else(|| {
                Status::not_found(
                    "linked application is not known to this edge",
                )
            })?;
        Ok(Response::new(LinkedApplicationStatusResponse {
            captured_at: Some(timestamp(SystemTime::now())?),
            application: Some(proto_status(application)?),
        }))
    }

    async fn start_linked_application(
        &self,
        request: Request<LinkedApplicationCommandRequest>,
    ) -> Result<Response<LinkedApplicationCommandResponse>, Status> {
        self.command(request.into_inner(), "start", true)
    }

    async fn stop_linked_application(
        &self,
        request: Request<LinkedApplicationCommandRequest>,
    ) -> Result<Response<LinkedApplicationCommandResponse>, Status> {
        self.command(request.into_inner(), "stop", true)
    }

    async fn restart_linked_application(
        &self,
        request: Request<LinkedApplicationCommandRequest>,
    ) -> Result<Response<LinkedApplicationCommandResponse>, Status> {
        self.command(request.into_inner(), "restart", true)
    }

    async fn send_linked_command(
        &self,
        request: Request<LinkedApplicationCommandRequest>,
    ) -> Result<Response<LinkedApplicationCommandResponse>, Status> {
        let request = request.into_inner();
        let command = request.command.clone();
        self.command(request, &command, false)
    }
}

pub fn create_linked_application_manager(
    state: AppState
) -> LinkedApplicationManagerServer<LinkedApplicationManagerService> {
    LinkedApplicationManagerServer::new(LinkedApplicationManagerService {
        state,
    })
}

fn domain_id(
    value: Option<LinkedApplicationId>
) -> Result<(FleetName, String), Status> {
    let value = value.ok_or_else(|| {
        Status::invalid_argument("linked application id is required")
    })?;
    if !value.transport.is_empty() && value.transport != "orbit" {
        return Err(Status::unimplemented(
            "this edge has no controller for that linked transport",
        ));
    }
    let fleet = FleetName::try_new(&value.fleet_name)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    claviron::orbit::link::application::segment::check_application_name(
        &value.name,
    )
    .map_err(link_status)?;
    Ok((fleet, value.name))
}

fn proto_status(
    value: LinkApplication
) -> Result<LinkedApplicationStatus, Status> {
    let connected_lanes = value.peers.len() as u32;
    let hosted = hosted_status(&value)?;
    Ok(LinkedApplicationStatus {
        info: Some(LinkedApplicationInfo {
            id: Some(LinkedApplicationId {
                fleet_name: value.fleet.to_string(),
                name: value.name,
                transport: "orbit".to_owned(),
            }),
            runtime: value.runtime.unwrap_or_default(),
        }),
        link: if connected_lanes == 0 {
            LinkReachability::Disconnected
        } else {
            LinkReachability::Connected
        } as i32,
        connected_lanes,
        hosted,
        lanes: value
            .peers
            .into_iter()
            .map(|peer| LinkedApplicationLane {
                lane: peer.lane as u32,
                pid: peer.pid,
                incarnation: peer.incarnation,
            })
            .collect(),
    })
}

fn hosted_status(
    value: &LinkApplication
) -> Result<Option<ListApplicationsResponse>, Status> {
    if value.reports.is_empty() {
        return Ok(None);
    }
    let mut applications = BTreeMap::<_, Vec<FleetApplicationPlacement>>::new();
    let mut members_reporting = 0u32;
    for rows in &value.reports {
        let snapshot = match decode_link_snapshot_rows(rows) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(%error, "invalid linked application snapshot");
                continue;
            }
        };
        members_reporting += 1;
        for application in snapshot.applications {
            applications
                .entry(application.id)
                .or_default()
                .extend(application.placements);
        }
    }
    if members_reporting == 0 {
        return Ok(None);
    }
    let applications = applications
        .into_iter()
        .map(|(id, mut placements)| {
            placements.sort_by_key(|placement| placement.member);
            application_status(FleetApplicationStatus { id, placements })
        })
        .collect::<Result<_, _>>()?;
    Ok(Some(ListApplicationsResponse {
        captured_at: Some(timestamp(SystemTime::now())?),
        members_expected: value.peers.len() as u32,
        members_reporting,
        applications,
    }))
}

fn timestamp(value: SystemTime) -> Result<Timestamp, Status> {
    let elapsed = value.duration_since(UNIX_EPOCH).map_err(|_| {
        Status::internal("linked application timestamp precedes the Unix epoch")
    })?;
    Ok(Timestamp {
        seconds: i64::try_from(elapsed.as_secs()).map_err(|_| {
            Status::internal(
                "linked application timestamp exceeds protobuf range",
            )
        })?,
        nanos: elapsed.subsec_nanos() as i32,
    })
}

fn link_status(error: LinkError) -> Status {
    match error {
        LinkError::InvalidName { .. } | LinkError::Malformed(_) => {
            Status::invalid_argument(error.to_string())
        }
        LinkError::NoConsumer(_) => {
            Status::failed_precondition(error.to_string())
        }
        _ => Status::unavailable(error.to_string()),
    }
}
