//! Shared protobuf dispatch for user and authorization management handlers.
//!
//! Bind `dyn GrpcAccessPolicy` and the selected native managers in the application
//! registry. Authentication is independent of the managed record and of mTLS
//! channel admission; no certificate name or client-supplied subject is trusted.
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;

use claviron::auth::AnyAuthenticated;
use claviron::runtime::AppState;
use tonic::{Request, Response, Status};

#[cfg(feature = "authorization")]
use claviron::auth::authorization as domain;
#[cfg(not(feature = "authorization"))]
use claviron::auth::users as domain;

use crate::proto::users as wire;
use wire::user_management_server::{UserManagement, UserManagementServer};
#[cfg(feature = "users")]
mod accounts;
#[cfg(feature = "authorization")]
mod authorization;
mod codec;
use codec::*;

/// Explicit host-owned work bounds in `grpc.yaml`'s `user_management` section.
/// Tonic's default inbound message bound remains in force as well.
#[derive(Clone, Copy, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_page_size: NonZeroU32,
    pub max_document_bytes: NonZeroUsize,
    pub max_assignment_members: NonZeroUsize,
}

pub(crate) struct Service {
    pub(super) state: AppState,
}

enum Manager {
    #[cfg(feature = "users")]
    Users(Arc<dyn claviron::auth::users::UserManager>),
    #[cfg(feature = "authorization")]
    Authorization(Arc<dyn domain::RolePermissionManager>),
}

macro_rules! dispatch {
    ($manager:expr, $method:ident, $actor:expr, $input:expr) => {
        match $manager {
            #[cfg(feature = "users")]
            Manager::Users(manager) => {
                accounts::$method(manager.as_ref(), $actor, $input).await
            }
            #[cfg(feature = "authorization")]
            Manager::Authorization(manager) => {
                authorization::$method(manager.as_ref(), $actor, $input).await
            }
        }
    };
}

impl Service {
    pub(super) fn limits(&self) -> Result<Limits, Status> {
        self.state
            .registry_ref()
            .resolve::<crate::server::provider::GrpcServiceProvider>()
            .and_then(|provider| provider.config().user_management)
            .ok_or_else(|| {
                Status::failed_precondition(
                    "user management limits are not configured",
                )
            })
    }

    pub(super) fn actor<T>(
        &self,
        request: &Request<T>,
        method: &str,
    ) -> Result<AnyAuthenticated, Status> {
        let admission = request
            .extensions()
            .get::<crate::server::access::Admission>()
            .ok_or_else(|| {
                Status::unauthenticated("management admission is required")
            })?;
        if admission.operation
            != format!("/claviron.users.UserManagement/{method}")
        {
            return Err(Status::permission_denied(
                "management admission target mismatch",
            ));
        }
        admission.actor.clone().ok_or_else(|| {
            Status::failed_precondition(
                "management requires an application actor from GrpcAccessPolicy",
            )
        })
    }
    fn manager(
        &self,
        resource: domain::Resource,
    ) -> Result<Manager, Status> {
        match resource {
            #[cfg(feature = "users")]
            domain::Resource::User => self
                .state
                .registry_ref()
                .resolve_dyn::<dyn claviron::auth::users::UserManager>()
                .map(Manager::Users),
            #[cfg(feature = "authorization")]
            domain::Resource::Role | domain::Resource::Permission => self
                .state
                .registry_ref()
                .resolve_dyn::<dyn domain::RolePermissionManager>()
                .map(Manager::Authorization),
            #[allow(unreachable_patterns)]
            _ => None,
        }
        .ok_or_else(|| {
            Status::unimplemented("management provider is not registered")
        })
    }
}

#[tonic::async_trait]
impl UserManagement for Service {
    async fn get_schema(
        &self,
        request: Request<wire::GetSchemaRequest>,
    ) -> Result<Response<wire::ManagementSchema>, Status> {
        let actor = self.actor(&request, "GetSchema")?;
        let resource = resource(request.into_inner().resource)?;
        let manager = self.manager(resource)?;
        dispatch!(manager, schema, actor.as_ref(), resource).map(Response::new)
    }

    async fn list_records(
        &self,
        request: Request<wire::ListRecordsRequest>,
    ) -> Result<Response<wire::ListRecordsResponse>, Status> {
        let actor = self.actor(&request, "ListRecords")?;
        let input = request.into_inner();
        let resource = resource(input.resource)?;
        let manager = self.manager(resource)?;
        if input.page_size > self.limits()?.max_page_size.get() {
            return Err(Status::invalid_argument(
                "page_size exceeds the configured limit",
            ));
        }
        let input = domain::List {
            resource,
            page_size: NonZeroU32::new(input.page_size).ok_or_else(|| {
                Status::invalid_argument("page_size must be positive")
            })?,
            cursor: input.cursor,
            query: input.query,
        };
        dispatch!(manager, list, actor.as_ref(), input).map(Response::new)
    }

    async fn get_record(
        &self,
        request: Request<wire::GetRecordRequest>,
    ) -> Result<Response<wire::ManagedRecord>, Status> {
        let actor = self.actor(&request, "GetRecord")?;
        let key = key(request.into_inner().key)?;
        let manager = self.manager(key.resource)?;
        dispatch!(manager, get, actor.as_ref(), key).map(Response::new)
    }

    async fn create_record(
        &self,
        request: Request<wire::CreateRecordRequest>,
    ) -> Result<Response<wire::RecordMutationResult>, Status> {
        let actor = self.actor(&request, "CreateRecord")?;
        let input = request.into_inner();
        let resource = resource(input.resource)?;
        let manager = self.manager(resource)?;
        let input = domain::Create {
            resource,
            schema_revision: required(
                input.schema_revision,
                "schema_revision",
            )?,
            data: bounded_document(&input.data_json, self.limits()?)?,
        };
        dispatch!(manager, create, actor.as_ref(), input).map(Response::new)
    }

    async fn update_record(
        &self,
        request: Request<wire::UpdateRecordRequest>,
    ) -> Result<Response<wire::RecordMutationResult>, Status> {
        let actor = self.actor(&request, "UpdateRecord")?;
        let input = request.into_inner();
        let key = key(input.key)?;
        let manager = self.manager(key.resource)?;
        let input = domain::Update {
            key,
            revision: required(input.revision, "revision")?,
            schema_revision: required(
                input.schema_revision,
                "schema_revision",
            )?,
            changes: bounded_document(&input.changes_json, self.limits()?)?,
        };
        dispatch!(manager, update, actor.as_ref(), input).map(Response::new)
    }

    async fn delete_record(
        &self,
        request: Request<wire::DeleteRecordRequest>,
    ) -> Result<Response<()>, Status> {
        let actor = self.actor(&request, "DeleteRecord")?;
        let input = request.into_inner();
        let key = key(input.key)?;
        let manager = self.manager(key.resource)?;
        let input = domain::Delete {
            key,
            revision: required(input.revision, "revision")?,
        };
        dispatch!(manager, delete, actor.as_ref(), input)?;
        Ok(Response::new(()))
    }

    async fn get_assignment_schema(
        &self,
        request: Request<wire::GetAssignmentSchemaRequest>,
    ) -> Result<Response<wire::AssignmentSchema>, Status> {
        #[cfg(feature = "authorization")]
        {
            authorization::get_assignment_schema(self, request).await
        }
        #[cfg(not(feature = "authorization"))]
        {
            self.actor(&request, "GetAssignmentSchema")?;
            Err(Status::unimplemented("authorization is not enabled"))
        }
    }

    async fn get_assignments(
        &self,
        request: Request<wire::GetAssignmentsRequest>,
    ) -> Result<Response<wire::Assignments>, Status> {
        #[cfg(feature = "authorization")]
        {
            authorization::get_assignments(self, request).await
        }
        #[cfg(not(feature = "authorization"))]
        {
            self.actor(&request, "GetAssignments")?;
            Err(Status::unimplemented("authorization is not enabled"))
        }
    }

    async fn replace_assignments(
        &self,
        request: Request<wire::ReplaceAssignmentsRequest>,
    ) -> Result<Response<wire::AssignmentMutationResult>, Status> {
        #[cfg(feature = "authorization")]
        {
            authorization::replace_assignments(self, request).await
        }
        #[cfg(not(feature = "authorization"))]
        {
            self.actor(&request, "ReplaceAssignments")?;
            Err(Status::unimplemented("authorization is not enabled"))
        }
    }
}

pub(crate) fn create_service(state: AppState) -> UserManagementServer<Service> {
    UserManagementServer::new(Service { state })
}

#[cfg(test)]
#[path = "../../../tests/users.rs"]
mod tests;
