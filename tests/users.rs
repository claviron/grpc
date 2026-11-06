use super::*;
use async_trait::async_trait;
use std::sync::Arc;
use tonic::Code;

#[test]
fn management_input_rejects_invalid_resource_key_and_json() {
    assert_eq!(resource(0).unwrap_err().code(), Code::InvalidArgument);
    assert_eq!(resource(i32::MAX).unwrap_err().code(), Code::InvalidArgument);
    assert_eq!(key(None).unwrap_err().code(), Code::InvalidArgument);
    assert!(document(b"[]").is_err());
    assert!(document(b"null").is_err());
    assert!(document(b"not-json").is_err());
    assert!(required(String::new(), "revision").is_err());
    let value =
        document(br#"{"counter":18446744073709551615,"clear":null}"#).unwrap();
    assert_eq!(value["counter"].as_u64(), Some(u64::MAX));
    assert!(value["clear"].is_null());
}

#[test]
fn management_status_and_validation_preserve_safe_contract() {
    use domain::ManagementError as E;
    for (error, code) in [
        (E::Unsupported, Code::Unimplemented),
        (E::Forbidden, Code::PermissionDenied),
        (E::NotFound, Code::NotFound),
        (E::Conflict, Code::Aborted),
        (E::SchemaChanged, Code::FailedPrecondition),
        (E::Unavailable, Code::Unavailable),
    ] {
        assert_eq!(status(error).code(), code);
    }
    let value = mutation(Err(E::Validation(vec![domain::Violation {
        path: "/label".into(),
        code: "required".into(),
        message: "A label is required.".into(),
    }])))
    .unwrap();
    let Some(wire::record_mutation_result::Outcome::Validation(failure)) =
        value.outcome
    else {
        panic!("validation must not appear as a committed record")
    };
    assert_eq!(failure.violations[0].path, "/label");
    assert_eq!(
        mutation(Err(E::Validation(vec![]))).unwrap_err().code(),
        Code::Internal
    );
}

use claviron::auth::Authenticated;
use std::any::Any;
use std::borrow::Cow;
use std::sync::Mutex;

#[derive(Clone)]
struct Actor(&'static str);
impl Authenticated for Actor {
    fn auth_subject(&self) -> Cow<'_, str> {
        self.0.into()
    }
    fn auth_identifier(&self) -> &str {
        self.0
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
fn admitted<T>(value: T) -> Request<T> {
    let mut request = Request::new(value);
    let operation = std::any::type_name::<T>()
        .rsplit("::")
        .next()
        .unwrap()
        .strip_suffix("Request")
        .unwrap();
    request.extensions_mut().insert(crate::server::access::Admission {
        operation: format!("/claviron.users.UserManagement/{operation}"),
        actor: Some(Arc::new(Actor("operator"))),
    });
    request
}
async fn setup() -> Service {
    let state = AppState::standalone("management-unit-test", ".");
    let provider =
        Arc::new(crate::server::provider::GrpcServiceProvider::new(&state));
    let config = serde_yaml::from_str("user_management: {max_page_size: 2, max_document_bytes: 256, max_assignment_members: 2}").unwrap();
    claviron::runtime::congif::Configurable::configure(
        provider.as_ref(),
        &config,
    )
    .await
    .unwrap();
    state.registry_ref().insert(provider).unwrap();
    Service { state }
}

#[derive(Default)]
struct Capture(Mutex<Vec<(String, &'static str, domain::Resource)>>);
impl Capture {
    fn called(
        &self,
        actor: &dyn Authenticated,
        name: &'static str,
        resource: domain::Resource,
    ) {
        self.0.lock().unwrap().push((
            actor.auth_subject().into_owned(),
            name,
            resource,
        ));
    }
}
#[cfg(feature = "users")]
#[derive(Default)]
struct Users(Capture);
#[cfg(feature = "authorization")]
#[derive(Default)]
struct Catalog(Capture);

fn output(key: domain::RecordKey) -> domain::Record {
    domain::Record {
        key,
        revision: "record-2".into(),
        data: document(br#"{"counter":18446744073709551615}"#).unwrap(),
    }
}

macro_rules! impl_manager {
    ($target:ty, $interface:path, $($extra:item),* $(,)?) => {
        #[async_trait]
        impl $interface for $target {
    async fn schema(
        &self,
        actor: &dyn Authenticated,
        resource: domain::Resource,
    ) -> domain::Result<domain::Schema> {
        self.0.called(actor, "schema", resource);
        Ok(domain::Schema {
            resource,
            revision: "schema-1".into(),
            record: domain::Document::new(),
            create: None,
            update: Some(domain::Form {
                schema: domain::Document::new(),
                ui: Some(domain::Document::new()),
            }),
            operations: vec![
                domain::Operation::Read,
                domain::Operation::Update,
            ],
        })
    }
    async fn list(
        &self,
        actor: &dyn Authenticated,
        input: domain::List,
    ) -> domain::Result<domain::Page> {
        self.0.called(actor, "list", input.resource);
        assert_eq!(input.page_size.get(), 2);
        assert_eq!(input.cursor.as_deref(), Some("cursor-1"));
        assert_eq!(input.query.as_deref(), Some("query"));
        Ok(domain::Page {
            records: vec![output(domain::RecordKey {
                resource: input.resource,
                reference: "record-1".into(),
            })],
            next_cursor: Some("cursor-2".into()),
        })
    }
    async fn get(
        &self,
        actor: &dyn Authenticated,
        input: domain::RecordKey,
    ) -> domain::Result<domain::Record> {
        self.0.called(actor, "get", input.resource);
        Ok(output(input))
    }
    async fn create(
        &self,
        actor: &dyn Authenticated,
        input: domain::Create,
    ) -> domain::Result<domain::Record> {
        self.0.called(actor, "create", input.resource);
        assert_eq!(input.schema_revision, "schema-1");
        assert_eq!(input.data["label"], "created");
        Ok(output(domain::RecordKey {
            resource: input.resource,
            reference: "created".into(),
        }))
    }
    async fn update(
        &self,
        actor: &dyn Authenticated,
        input: domain::Update,
    ) -> domain::Result<domain::Record> {
        self.0.called(actor, "update", input.key.resource);
        if input.revision == "stale" {
            return Err(domain::ManagementError::Conflict);
        }
        if input.changes.contains_key("denied") {
            return Err(domain::ManagementError::Forbidden);
        }
        if input.changes.contains_key("invalid") {
            return Err(domain::ManagementError::Validation(vec![
                domain::Violation {
                    path: "/invalid".into(),
                    code: "invalid".into(),
                    message: "Invalid value.".into(),
                },
            ]));
        }
        assert_eq!(input.revision, "record-1");
        assert_eq!(input.schema_revision, "schema-1");
        assert_eq!(input.changes.len(), 2);
        assert_eq!(input.changes["counter"].as_u64(), Some(u64::MAX));
        assert!(input.changes["clear"].is_null());
        Ok(output(input.key))
    }
    async fn delete(
        &self,
        actor: &dyn Authenticated,
        input: domain::Delete,
    ) -> domain::Result<()> {
        self.0.called(actor, "delete", input.key.resource);
        assert_eq!(input.revision, "record-1");
        Ok(())
    }
            $($extra)*
        }
    };
}
#[cfg(feature = "users")]
impl_manager!(Users, claviron::auth::users::UserManager,);
#[cfg(feature = "authorization")]
impl_manager!(
    Catalog,
    domain::RolePermissionManager,
    async fn assignment_schema(
        &self,
        actor: &dyn Authenticated,
        relation: domain::Relation,
    ) -> domain::Result<domain::AssignmentSchema> {
        self.0.called(actor, "assignment_schema", relation.member());
        Ok(domain::AssignmentSchema {
            relation,
            revision: "assignments-schema-1".into(),
            operations: vec![
                domain::Operation::ReadAssignments,
                domain::Operation::ReplaceAssignments,
            ],
        })
    },
    async fn assignments(
        &self,
        actor: &dyn Authenticated,
        key: domain::AssignmentKey,
    ) -> domain::Result<domain::Assignments> {
        self.0.called(actor, "assignments", key.relation.member());
        Ok(domain::Assignments {
            key,
            revision: "assignments-1".into(),
            members: vec!["existing".into()],
        })
    },
    async fn replace_assignments(
        &self,
        actor: &dyn Authenticated,
        input: domain::ReplaceAssignments,
    ) -> domain::Result<domain::Assignments> {
        self.0.called(
            actor,
            "replace_assignments",
            input.key.relation.member(),
        );
        if input.revision != "assignments-1" {
            return Err(domain::ManagementError::Conflict);
        }
        Ok(domain::Assignments {
            key: input.key,
            revision: "assignments-2".into(),
            members: input.members,
        })
    }
);

async fn exercise_crud(
    service: &Service,
    resource: wire::Resource,
) {
    let key = || {
        Some(wire::RecordKey {
            resource: resource.into(),
            reference: "record-1".into(),
        })
    };
    let schema = service
        .get_schema(admitted(wire::GetSchemaRequest {
            resource: resource.into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(schema.revision, "schema-1");
    assert!(schema.create.is_none());
    assert_eq!(schema.update.unwrap().ui_schema_json, Some(b"{}".to_vec()));
    let page = service
        .list_records(admitted(wire::ListRecordsRequest {
            resource: resource.into(),
            page_size: 2,
            cursor: Some("cursor-1".into()),
            query: Some("query".into()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page.next_cursor.as_deref(), Some("cursor-2"));
    assert_eq!(page.records.len(), 1);
    let value = service
        .get_record(admitted(wire::GetRecordRequest { key: key() }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(value.key.unwrap().resource, resource as i32);
    assert_eq!(
        document(&value.data_json).unwrap()["counter"].as_u64(),
        Some(u64::MAX)
    );
    let created = service
        .create_record(admitted(wire::CreateRecordRequest {
            resource: resource.into(),
            schema_revision: "schema-1".into(),
            data_json: br#"{"label":"created"}"#.to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        created.outcome,
        Some(wire::record_mutation_result::Outcome::Record(_))
    ));
    let update = |revision: &str, changes: &[u8]| {
        admitted(wire::UpdateRecordRequest {
            key: key(),
            revision: revision.into(),
            schema_revision: "schema-1".into(),
            changes_json: changes.to_vec(),
        })
    };
    let updated = service
        .update_record(update(
            "record-1",
            br#"{"counter":18446744073709551615,"clear":null}"#,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        updated.outcome,
        Some(wire::record_mutation_result::Outcome::Record(_))
    ));
    let rejected = service
        .update_record(update("record-1", br#"{"invalid":true}"#))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        rejected.outcome,
        Some(wire::record_mutation_result::Outcome::Validation(_))
    ));
    assert_eq!(
        service.update_record(update("stale", b"{}")).await.unwrap_err().code(),
        Code::Aborted
    );
    assert_eq!(
        service
            .update_record(update("record-1", br#"{"denied":true}"#))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    service
        .delete_record(admitted(wire::DeleteRecordRequest {
            key: key(),
            revision: "record-1".into(),
        }))
        .await
        .unwrap();
    assert_eq!(
        service
            .list_records(admitted(wire::ListRecordsRequest {
                resource: resource.into(),
                page_size: 0,
                cursor: None,
                query: None
            }))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        service.update_record(update("", b"{}")).await.unwrap_err().code(),
        Code::InvalidArgument
    );
}

#[cfg(feature = "users")]
fn bind_users(service: &Service) -> Arc<Users> {
    let manager = Arc::new(Users::default());
    service.state.registry_ref().insert(manager.clone()).unwrap();
    service
        .state
        .registry_ref()
        .bind_dyn::<dyn claviron::auth::users::UserManager, Users>(|value| {
            value
        })
        .unwrap();
    manager
}
#[cfg(feature = "authorization")]
fn bind_catalog(service: &Service) -> Arc<Catalog> {
    let manager = Arc::new(Catalog::default());
    service.state.registry_ref().insert(manager.clone()).unwrap();
    service
        .state
        .registry_ref()
        .bind_dyn::<dyn domain::RolePermissionManager, Catalog>(|value| value)
        .unwrap();
    manager
}

#[cfg(feature = "users")]
#[tokio::test]
async fn management_user_crud_needs_no_authorization_manager() {
    let service = setup().await;
    let users = bind_users(&service);
    exercise_crud(&service, wire::Resource::User).await;
    assert_eq!(users.0.0.lock().unwrap().len(), 9);
    assert!(
        users
            .0
            .0
            .lock()
            .unwrap()
            .iter()
            .all(|(actor, _, resource)| actor == "operator"
                && *resource == domain::Resource::User)
    );
    assert_eq!(
        service
            .get_schema(admitted(wire::GetSchemaRequest {
                resource: wire::Resource::Role.into()
            }))
            .await
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
    assert_eq!(
        service
            .get_assignments(admitted(wire::GetAssignmentsRequest {
                key: Some(wire::AssignmentKey {
                    relation: wire::Relation::UserRoles.into(),
                    reference: "record-1".into()
                })
            }))
            .await
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
}

#[cfg(feature = "authorization")]
#[tokio::test]
async fn management_catalog_and_user_pivots_need_no_user_manager() {
    let service = setup().await;
    let catalog = bind_catalog(&service);
    exercise_crud(&service, wire::Resource::Role).await;
    exercise_crud(&service, wire::Resource::Permission).await;
    for relation in [
        wire::Relation::UserRoles,
        wire::Relation::UserPermissions,
        wire::Relation::RolePermissions,
    ] {
        let key = || {
            Some(wire::AssignmentKey {
                relation: relation.into(),
                reference: "owner".into(),
            })
        };
        let schema = service
            .get_assignment_schema(admitted(wire::GetAssignmentSchemaRequest {
                relation: relation.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(schema.revision, "assignments-schema-1");
        assert_eq!(schema.operations.len(), 2);
        let current = service
            .get_assignments(admitted(wire::GetAssignmentsRequest {
                key: key(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(current.members, ["existing"]);
        for members in [vec![], vec!["first".into(), "second".into()]] {
            let result = service
                .replace_assignments(admitted(
                    wire::ReplaceAssignmentsRequest {
                        key: key(),
                        revision: "assignments-1".into(),
                        members: members.clone(),
                    },
                ))
                .await
                .unwrap()
                .into_inner();
            let Some(wire::assignment_mutation_result::Outcome::Assignments(
                value,
            )) = result.outcome
            else {
                panic!("expected assignments")
            };
            assert_eq!(value.members, members);
            assert_eq!(value.revision, "assignments-2");
        }
        assert_eq!(
            service
                .replace_assignments(admitted(
                    wire::ReplaceAssignmentsRequest {
                        key: key(),
                        revision: "old".into(),
                        members: vec![]
                    }
                ))
                .await
                .unwrap_err()
                .code(),
            Code::Aborted
        );
    }
    assert_eq!(
        service
            .get_schema(admitted(wire::GetSchemaRequest {
                resource: wire::Resource::User.into()
            }))
            .await
            .unwrap_err()
            .code(),
        Code::Unimplemented
    );
    assert!(catalog.0.0.lock().unwrap().iter().all(
        |(actor, _, resource)| actor == "operator"
            && matches!(
                resource,
                domain::Resource::Role | domain::Resource::Permission
            )
    ));
}

#[cfg(all(feature = "users", feature = "authorization"))]
#[tokio::test]
async fn management_both_managers_receive_only_their_resource_calls() {
    let service = setup().await;
    let users = bind_users(&service);
    let catalog = bind_catalog(&service);
    for resource in
        [wire::Resource::User, wire::Resource::Role, wire::Resource::Permission]
    {
        service
            .get_schema(admitted(wire::GetSchemaRequest {
                resource: resource.into(),
            }))
            .await
            .unwrap();
    }
    assert_eq!(users.0.0.lock().unwrap().len(), 1);
    assert_eq!(catalog.0.0.lock().unwrap().len(), 2);
    assert_eq!(users.0.0.lock().unwrap()[0].2, domain::Resource::User);
}

#[tokio::test]
async fn management_admission_has_no_metadata_or_certificate_name_fallback() {
    let service = setup().await;
    let mut request = Request::new(wire::GetSchemaRequest {
        resource: wire::Resource::User.into(),
    });
    request.metadata_mut().insert("x-user-id", "operator".parse().unwrap());
    request
        .metadata_mut()
        .insert("authorization", "Bearer unverified".parse().unwrap());
    assert_eq!(
        service.get_schema(request).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    let request = admitted(wire::GetSchemaRequest {
        resource: wire::Resource::User.into(),
    });
    assert_eq!(
        service.get_schema(request).await.unwrap_err().code(),
        Code::Unimplemented
    );
    let missing =
        Service { state: AppState::standalone("no-management-auth", ".") };
    let mut peer_only = admitted(wire::GetSchemaRequest {
        resource: wire::Resource::User.into(),
    });
    peer_only
        .extensions_mut()
        .get_mut::<crate::server::access::Admission>()
        .unwrap()
        .actor = None;
    assert_eq!(
        missing.get_schema(peer_only).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn management_admission_cannot_be_reused_for_another_operation() {
    let service = setup().await;
    let mut request = admitted(wire::GetSchemaRequest {
        resource: wire::Resource::User.into(),
    });
    request
        .extensions_mut()
        .get_mut::<crate::server::access::Admission>()
        .unwrap()
        .operation = "/example.Admin/Inspect".into();
    assert_eq!(
        service.get_schema(request).await.unwrap_err().code(),
        Code::PermissionDenied
    );
}

#[cfg(feature = "authorization")]
#[tokio::test]
async fn management_bad_assignment_inputs_never_reach_provider() {
    let service = setup().await;
    let catalog = bind_catalog(&service);
    for members in [vec![String::new()], vec!["same".into(), "same".into()]] {
        assert_eq!(
            service
                .replace_assignments(admitted(
                    wire::ReplaceAssignmentsRequest {
                        key: Some(wire::AssignmentKey {
                            relation: wire::Relation::UserRoles.into(),
                            reference: "owner".into()
                        }),
                        revision: "assignments-1".into(),
                        members,
                    }
                ))
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
    assert_eq!(
        service
            .get_assignment_schema(admitted(wire::GetAssignmentSchemaRequest {
                relation: 0
            }))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert!(catalog.0.0.lock().unwrap().is_empty());
}

#[cfg(feature = "users")]
#[tokio::test]
async fn management_limits_bound_work_before_delegation_and_follow_reload() {
    let service = setup().await;
    let users = bind_users(&service);
    let list = || {
        admitted(wire::ListRecordsRequest {
            resource: wire::Resource::User.into(),
            page_size: 3,
            cursor: None,
            query: None,
        })
    };
    assert_eq!(
        service.list_records(list()).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let create = || {
        admitted(wire::CreateRecordRequest {
            resource: wire::Resource::User.into(),
            schema_revision: "schema-1".into(),
            data_json: vec![b' '; 257],
        })
    };
    assert_eq!(
        service.create_record(create()).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    assert!(users.0.0.lock().unwrap().is_empty());
    let provider = service
        .state
        .registry_ref()
        .resolve::<crate::server::provider::GrpcServiceProvider>()
        .unwrap();
    let config = serde_yaml::from_str("user_management: {max_page_size: 1, max_document_bytes: 1, max_assignment_members: 1}").unwrap();
    claviron::runtime::congif::ConfigObserver::config_changed(
        provider.as_ref(),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(service.limits().unwrap().max_page_size.get(), 1);
    assert_eq!(
        service
            .create_record(admitted(wire::CreateRecordRequest {
                resource: wire::Resource::User.into(),
                schema_revision: "schema-1".into(),
                data_json: b"{}".to_vec()
            }))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    let config = crate::server::config::GrpcConfig::default();
    claviron::runtime::congif::ConfigObserver::config_changed(
        provider.as_ref(),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(
        service.create_record(create()).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert!(users.0.0.lock().unwrap().is_empty());
}

#[test]
fn management_limits_require_explicit_positive_bounds() {
    for text in [
        "user_management: {max_page_size: 0, max_document_bytes: 1, max_assignment_members: 1}",
        "user_management: {max_page_size: 1, max_document_bytes: 0, max_assignment_members: 1}",
        "user_management: {max_page_size: 1, max_document_bytes: 1, max_assignment_members: 0}",
        "user_management: {}",
    ] {
        assert!(
            serde_yaml::from_str::<crate::server::config::GrpcConfig>(text)
                .is_err()
        );
    }
}

#[cfg(feature = "authorization")]
#[tokio::test]
async fn management_assignment_limit_rejects_before_provider() {
    let service = setup().await;
    let catalog = bind_catalog(&service);
    assert_eq!(
        service
            .replace_assignments(admitted(wire::ReplaceAssignmentsRequest {
                key: Some(wire::AssignmentKey {
                    relation: wire::Relation::UserRoles.into(),
                    reference: "owner".into()
                }),
                revision: "assignments-1".into(),
                members: vec!["first".into(), "second".into(), "third".into()],
            }))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert!(catalog.0.0.lock().unwrap().is_empty());
}

#[cfg(all(feature = "users", feature = "authorization"))]
#[tokio::test]
async fn management_single_tonic_service_routes_both_capabilities() {
    use http_body_util::BodyExt;
    use prost::Message;
    use tower::ServiceExt;
    let service = setup().await;
    let users = bind_users(&service);
    let catalog = bind_catalog(&service);
    let routes =
        tonic::service::Routes::new(create_service(service.state)).prepare();
    for resource in [wire::Resource::User, wire::Resource::Role] {
        let payload = wire::GetSchemaRequest { resource: resource.into() }
            .encode_to_vec();
        let mut framed = vec![0];
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(&payload);
        let mut request = http::Request::builder()
            .method("POST")
            .uri("/claviron.users.UserManagement/GetSchema")
            .version(http::Version::HTTP_2)
            .header("content-type", "application/grpc")
            .body(tonic::body::Body::new(claviron::http::bytes_body(
                framed.into(),
            )))
            .unwrap();
        request.extensions_mut().insert(crate::server::access::Admission {
            operation: "/claviron.users.UserManagement/GetSchema".into(),
            actor: Some(Arc::new(Actor("operator"))),
        });
        let response = routes.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.trailers().unwrap().get("grpc-status").unwrap(), "0");
        let bytes = body.to_bytes();
        let schema = wire::ManagementSchema::decode(&bytes[5..]).unwrap();
        assert_eq!(schema.resource, resource as i32);
    }
    assert_eq!(users.0.0.lock().unwrap().len(), 1);
    assert_eq!(catalog.0.0.lock().unwrap().len(), 1);
}

#[cfg(feature = "users")]
#[tokio::test]
async fn management_gateway_supplies_the_policy_bound_actor_once() {
    use crate::access::{AccessError, GrpcAccessPolicy};
    use claviron::edge::OtherHandler;
    use claviron::http::ext::{ClientAuthStatus, ConnCtx, TlsInfo};
    use claviron::ssl::peer::PeerIdentity;
    use http_body_util::BodyExt;
    use prost::Message;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Binding(AtomicUsize);
    #[async_trait]
    impl GrpcAccessPolicy for Binding {
        async fn authorize(
            &self,
            peer: &PeerIdentity,
        ) -> Result<Option<AnyAuthenticated>, AccessError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            assert_eq!(*peer.common_names, ["operator"].map(Box::<str>::from));
            Ok(Some(Arc::new(Actor("policy-subject"))))
        }
    }
    let service = setup().await;
    let users = bind_users(&service);
    let binding = Arc::new(Binding(AtomicUsize::new(0)));
    service.state.registry_ref().insert(binding.clone()).unwrap();
    service
        .state
        .registry_ref()
        .bind_dyn::<dyn GrpcAccessPolicy, Binding>(|value| value)
        .unwrap();
    let routes =
        tonic::service::Routes::new(create_service(service.state.clone()))
            .prepare();
    let handler = crate::server::other::ManagementGrpcHandler::with_routes(
        routes,
        "management.example.test".into(),
    );
    let payload =
        wire::GetSchemaRequest { resource: wire::Resource::User.into() }
            .encode_to_vec();
    let mut frame = vec![0];
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    let mut request = http::Request::builder()
        .method("POST")
        .uri("/claviron.users.UserManagement/GetSchema")
        .version(http::Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("x-user-id", "attacker")
        .body(claviron::http::bytes_body(frame.into()))
        .unwrap();
    let mut connection = ConnCtx {
        state: Default::default(),
        listener: "management".parse().unwrap(),
        proto: Some(claviron::tls::Proto::H2),
        remote: "192.0.2.1:12345".parse().unwrap(),
        local_ip: "192.0.2.2".parse().unwrap(),
        local_port: 443,
        real_ip: None,
        country_code: None,
        tls: Some(TlsInfo {
            protocol_version: None,
            cipher_suite: None,
            client_auth: ClientAuthStatus::Verified,
            client_cert: Some(Arc::new(PeerIdentity {
                certificate: Arc::from([]),
                subject_dn: "CN=operator".into(),
                issuer_dn: "CN=example CA".into(),
                common_names: Box::new(["operator".into()]),
                subject_uris: Box::new([]),
            })),
        }),
    };
    // Stand in for the edge: prepare the connection as its acceptance would.
    let mut conn = claviron::http::ext::ConnStateBuilder::default();
    crate::server::other::prepare_connection(
        &service.state,
        &connection,
        &mut conn,
    );
    connection.state = conn.build();
    request.extensions_mut().insert(Arc::new(connection));
    let response = handler.call(request).await.unwrap();
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(body.trailers().unwrap().get("grpc-status").unwrap(), "0");
    assert_eq!(binding.0.load(Ordering::SeqCst), 1);
    assert_eq!(users.0.0.lock().unwrap()[0].0, "policy-subject");
}
