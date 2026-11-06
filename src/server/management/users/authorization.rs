//! Role, permission and assignment gRPC handlers.
use std::sync::Arc;

use claviron::auth::Authenticated;
use claviron::auth::authorization as domain;
use tonic::Status;

use super::{Service, codec};
use crate::proto::users as wire;

fn manager(
    service: &Service
) -> Result<Arc<dyn domain::RolePermissionManager>, Status> {
    service
        .state
        .registry_ref()
        .resolve_dyn::<dyn domain::RolePermissionManager>()
        .ok_or_else(|| {
            Status::unimplemented("authorization provider is not registered")
        })
}

pub(super) async fn schema(
    manager: &dyn domain::RolePermissionManager,
    actor: &dyn Authenticated,
    resource: domain::Resource,
) -> Result<wire::ManagementSchema, Status> {
    codec::schema(manager.schema(actor, resource).await.map_err(codec::status)?)
}

pub(super) async fn list(
    manager: &dyn domain::RolePermissionManager,
    actor: &dyn Authenticated,
    input: domain::List,
) -> Result<wire::ListRecordsResponse, Status> {
    let value = manager.list(actor, input).await.map_err(codec::status)?;
    Ok(wire::ListRecordsResponse {
        records: value
            .records
            .into_iter()
            .map(codec::record)
            .collect::<Result<_, _>>()?,
        next_cursor: value.next_cursor,
    })
}

pub(super) async fn get(
    manager: &dyn domain::RolePermissionManager,
    actor: &dyn Authenticated,
    key: domain::RecordKey,
) -> Result<wire::ManagedRecord, Status> {
    codec::record(manager.get(actor, key).await.map_err(codec::status)?)
}

pub(super) async fn create(
    manager: &dyn domain::RolePermissionManager,
    actor: &dyn Authenticated,
    input: domain::Create,
) -> Result<wire::RecordMutationResult, Status> {
    codec::mutation(manager.create(actor, input).await)
}

pub(super) async fn update(
    manager: &dyn domain::RolePermissionManager,
    actor: &dyn Authenticated,
    input: domain::Update,
) -> Result<wire::RecordMutationResult, Status> {
    codec::mutation(manager.update(actor, input).await)
}

pub(super) async fn delete(
    manager: &dyn domain::RolePermissionManager,
    actor: &dyn Authenticated,
    input: domain::Delete,
) -> Result<(), Status> {
    manager.delete(actor, input).await.map_err(codec::status)
}

pub(super) async fn get_assignment_schema(
    service: &Service,
    request: tonic::Request<wire::GetAssignmentSchemaRequest>,
) -> Result<tonic::Response<wire::AssignmentSchema>, Status> {
    let actor = service.actor(&request, "GetAssignmentSchema")?;
    let relation = codec::relation(request.into_inner().relation)?;
    let value = manager(service)?
        .assignment_schema(actor.as_ref(), relation)
        .await
        .map_err(codec::status)?;
    if value.revision.is_empty() {
        return Err(Status::internal(
            "provider returned an empty assignment schema revision",
        ));
    }
    Ok(tonic::Response::new(wire::AssignmentSchema {
        relation: codec::relation_out(value.relation),
        revision: value.revision,
        operations: codec::operations(value.operations)?,
    }))
}

pub(super) async fn get_assignments(
    service: &Service,
    request: tonic::Request<wire::GetAssignmentsRequest>,
) -> Result<tonic::Response<wire::Assignments>, Status> {
    let actor = service.actor(&request, "GetAssignments")?;
    let key = codec::assignment_key(request.into_inner().key)?;
    let value = manager(service)?
        .assignments(actor.as_ref(), key)
        .await
        .map_err(codec::status)?;
    Ok(tonic::Response::new(codec::assignments(value)?))
}

pub(super) async fn replace_assignments(
    service: &Service,
    request: tonic::Request<wire::ReplaceAssignmentsRequest>,
) -> Result<tonic::Response<wire::AssignmentMutationResult>, Status> {
    let actor = service.actor(&request, "ReplaceAssignments")?;
    let input = request.into_inner();
    if input.members.len() > service.limits()?.max_assignment_members.get() {
        return Err(Status::invalid_argument(
            "assignment members exceed the configured limit",
        ));
    }
    let input = domain::ReplaceAssignments {
        key: codec::assignment_key(input.key)?,
        revision: codec::required(input.revision, "revision")?,
        members: codec::members(input.members)?,
    };
    codec::assignment_mutation(
        manager(service)?.replace_assignments(actor.as_ref(), input).await,
    )
    .map(tonic::Response::new)
}
