//! User record gRPC handlers.

use claviron::auth::Authenticated;
use claviron::auth::users as domain;
use tonic::Status;

use super::codec;
use crate::proto::users as wire;

pub(super) async fn schema(
    manager: &dyn domain::UserManager,
    actor: &dyn Authenticated,
    resource: domain::Resource,
) -> Result<wire::ManagementSchema, Status> {
    codec::schema(manager.schema(actor, resource).await.map_err(codec::status)?)
}

pub(super) async fn list(
    manager: &dyn domain::UserManager,
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
    manager: &dyn domain::UserManager,
    actor: &dyn Authenticated,
    key: domain::RecordKey,
) -> Result<wire::ManagedRecord, Status> {
    codec::record(manager.get(actor, key).await.map_err(codec::status)?)
}

pub(super) async fn create(
    manager: &dyn domain::UserManager,
    actor: &dyn Authenticated,
    input: domain::Create,
) -> Result<wire::RecordMutationResult, Status> {
    codec::mutation(manager.create(actor, input).await)
}

pub(super) async fn update(
    manager: &dyn domain::UserManager,
    actor: &dyn Authenticated,
    input: domain::Update,
) -> Result<wire::RecordMutationResult, Status> {
    codec::mutation(manager.update(actor, input).await)
}

pub(super) async fn delete(
    manager: &dyn domain::UserManager,
    actor: &dyn Authenticated,
    input: domain::Delete,
) -> Result<(), Status> {
    manager.delete(actor, input).await.map_err(codec::status)
}
