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
    LinkedApplication as DomainLinkApplication,
};
use claviron::runtime::FleetName;
use prost_types::Timestamp;
use tonic::{Response, Status};

use super::{ApplicationManagerService, application_status};
use crate::proto::applications::{
    LinkApplicationCommandRequest, LinkApplicationCommandResponse,
    LinkApplicationId, LinkApplicationInfo, LinkApplicationLane,
    LinkApplicationStatus, LinkReachability, ListApplicationsResponse,
};

impl ApplicationManagerService {
    pub(super) fn link_service(
        &self
    ) -> Result<Arc<ApplicationService>, Status> {
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

    pub(super) fn link_command(
        &self,
        request: LinkApplicationCommandRequest,
        name: &str,
        target_required: bool,
    ) -> Result<Response<LinkApplicationCommandResponse>, Status> {
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
        self.link_service()?
            .forward_command(fleet, &link_name, name, request.payload, target)
            .map_err(link_status)?;
        Ok(Response::new(LinkApplicationCommandResponse {
            id: Some(LinkApplicationId {
                fleet_name: fleet.to_string(),
                name: link_name,
                transport: "orbit".to_owned(),
            }),
            accepted: true,
            application,
        }))
    }
}

pub(super) fn domain_id(
    value: Option<LinkApplicationId>
) -> Result<(FleetName, String), Status> {
    let value = value.ok_or_else(|| {
        Status::invalid_argument("Link application id is required")
    })?;
    if !value.transport.is_empty() && value.transport != "orbit" {
        return Err(Status::unimplemented(
            "this edge has no controller for that Link transport",
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

pub(super) fn proto_status(
    value: DomainLinkApplication
) -> Result<LinkApplicationStatus, Status> {
    let connected_lanes = value.peers.len() as u32;
    let hosted = hosted_status(&value)?;
    Ok(LinkApplicationStatus {
        info: Some(LinkApplicationInfo {
            id: Some(LinkApplicationId {
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
            .map(|peer| LinkApplicationLane {
                lane: peer.lane as u32,
                pid: peer.pid,
                incarnation: peer.incarnation,
            })
            .collect(),
    })
}

fn hosted_status(
    value: &DomainLinkApplication
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
                tracing::warn!(%error, "invalid Link application snapshot");
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

pub(super) fn timestamp(value: SystemTime) -> Result<Timestamp, Status> {
    let elapsed = value.duration_since(UNIX_EPOCH).map_err(|_| {
        Status::internal("Link application timestamp precedes the Unix epoch")
    })?;
    Ok(Timestamp {
        seconds: i64::try_from(elapsed.as_secs()).map_err(|_| {
            Status::internal(
                "Link application timestamp exceeds protobuf range",
            )
        })?,
        nanos: elapsed.subsec_nanos() as i32,
    })
}

pub(super) fn link_status(error: LinkError) -> Status {
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
