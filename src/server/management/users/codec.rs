use super::{domain, wire};
use crate::proto::management;
use tonic::Status;

pub(in crate::server) fn required(
    value: String,
    name: &str,
) -> Result<String, Status> {
    if value.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{name} must be nonempty"
        )));
    }
    Ok(value)
}

pub(in crate::server) fn resource(
    value: i32
) -> Result<domain::Resource, Status> {
    match wire::Resource::try_from(value) {
        #[cfg(feature = "users")]
        Ok(wire::Resource::User) => Ok(domain::Resource::User),
        #[cfg(feature = "authorization")]
        Ok(wire::Resource::Role) => Ok(domain::Resource::Role),
        #[cfg(feature = "authorization")]
        Ok(wire::Resource::Permission) => Ok(domain::Resource::Permission),
        Ok(wire::Resource::Unspecified) | Err(_) => {
            Err(Status::invalid_argument("invalid resource"))
        }
        #[allow(unreachable_patterns)]
        _ => Err(Status::unimplemented("management resource is not enabled")),
    }
}

fn resource_out(value: domain::Resource) -> Result<i32, Status> {
    match value {
        #[cfg(feature = "users")]
        domain::Resource::User => Ok(wire::Resource::User.into()),
        #[cfg(feature = "authorization")]
        domain::Resource::Role => Ok(wire::Resource::Role.into()),
        #[cfg(feature = "authorization")]
        domain::Resource::Permission => Ok(wire::Resource::Permission.into()),
        #[allow(unreachable_patterns)]
        _ => Err(Status::internal("provider returned a disabled resource")),
    }
}

pub(in crate::server) fn key(
    value: Option<wire::RecordKey>
) -> Result<domain::RecordKey, Status> {
    let value =
        value.ok_or_else(|| Status::invalid_argument("key is required"))?;
    Ok(domain::RecordKey {
        resource: resource(value.resource)?,
        reference: required(value.reference, "reference")?,
    })
}

pub(in crate::server) fn document(
    value: &[u8]
) -> Result<domain::Document, Status> {
    serde_json::from_slice(value).map_err(|_| {
        Status::invalid_argument("document must be a UTF-8 JSON object")
    })
}

pub(in crate::server) fn bounded_document(
    value: &[u8],
    limits: super::Limits,
) -> Result<domain::Document, Status> {
    if value.len() > limits.max_document_bytes.get() {
        return Err(Status::invalid_argument(
            "document exceeds the configured limit",
        ));
    }
    document(value)
}

fn json(value: &domain::Document) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(value)
        .map_err(|_| Status::internal("invalid provider document"))
}

pub(in crate::server) fn record(
    value: domain::Record
) -> Result<wire::ManagedRecord, Status> {
    if value.key.reference.is_empty() || value.revision.is_empty() {
        return Err(Status::internal("provider returned an invalid record"));
    }
    Ok(wire::ManagedRecord {
        key: Some(wire::RecordKey {
            resource: resource_out(value.key.resource)?,
            reference: value.key.reference,
        }),
        revision: value.revision,
        data_json: json(&value.data)?,
    })
}

fn form(value: domain::Form) -> Result<management::Form, Status> {
    Ok(management::Form {
        data_schema_json: json(&value.schema)?,
        ui_schema_json: value.ui.as_ref().map(json).transpose()?,
    })
}

pub(in crate::server) fn operations(
    values: Vec<domain::Operation>
) -> Result<Vec<i32>, Status> {
    values
        .into_iter()
        .map(|value| {
            Ok(match value {
                domain::Operation::List => wire::Operation::List,
                domain::Operation::Read => wire::Operation::Read,
                domain::Operation::Create => wire::Operation::Create,
                domain::Operation::Update => wire::Operation::Update,
                domain::Operation::Delete => wire::Operation::Delete,
                #[cfg(feature = "authorization")]
                domain::Operation::ReadAssignments => {
                    wire::Operation::ReadAssignments
                }
                #[cfg(feature = "authorization")]
                domain::Operation::ReplaceAssignments => {
                    wire::Operation::ReplaceAssignments
                }
                #[allow(unreachable_patterns)]
                _ => {
                    return Err(Status::internal(
                        "provider returned a disabled operation",
                    ));
                }
            }
            .into())
        })
        .collect()
}

pub(in crate::server) fn schema(
    value: domain::Schema
) -> Result<wire::ManagementSchema, Status> {
    if value.revision.is_empty() {
        return Err(Status::internal(
            "provider returned an empty schema revision",
        ));
    }
    Ok(wire::ManagementSchema {
        resource: resource_out(value.resource)?,
        revision: value.revision,
        record_schema_json: json(&value.record)?,
        create: value.create.map(form).transpose()?,
        update: value.update.map(form).transpose()?,
        operations: operations(value.operations)?,
    })
}

pub(in crate::server) fn status(error: domain::ManagementError) -> Status {
    use domain::ManagementError as E;
    let message = error.to_string();
    match error {
        E::Unsupported => Status::unimplemented(message),
        E::Forbidden => Status::permission_denied(message),
        E::NotFound => Status::not_found(message),
        E::Conflict => Status::aborted(message),
        E::SchemaChanged => Status::failed_precondition(message),
        E::Unavailable => Status::unavailable(message),
        E::Validation(_) => Status::invalid_argument(message),
    }
}

fn validation(
    values: Vec<domain::Violation>
) -> Result<management::ValidationFailure, Status> {
    if values.is_empty() {
        return Err(Status::internal(
            "provider returned empty validation feedback",
        ));
    }
    Ok(management::ValidationFailure {
        violations: values
            .into_iter()
            .map(|value| management::FieldViolation {
                path: value.path,
                code: value.code,
                message: value.message,
            })
            .collect(),
    })
}

pub(in crate::server) fn mutation(
    value: domain::Result<domain::Record>
) -> Result<wire::RecordMutationResult, Status> {
    use wire::record_mutation_result::Outcome;
    let outcome = match value {
        Ok(value) => Outcome::Record(record(value)?),
        Err(domain::ManagementError::Validation(values)) => {
            Outcome::Validation(validation(values)?)
        }
        Err(error) => return Err(status(error)),
    };
    Ok(wire::RecordMutationResult { outcome: Some(outcome) })
}

#[cfg(feature = "authorization")]
pub(in crate::server) fn relation(
    value: i32
) -> Result<domain::Relation, Status> {
    match wire::Relation::try_from(value) {
        Ok(wire::Relation::UserRoles) => Ok(domain::Relation::UserRoles),
        Ok(wire::Relation::UserPermissions) => {
            Ok(domain::Relation::UserPermissions)
        }
        Ok(wire::Relation::RolePermissions) => {
            Ok(domain::Relation::RolePermissions)
        }
        _ => Err(Status::invalid_argument("invalid relation")),
    }
}

#[cfg(feature = "authorization")]
pub(in crate::server) fn relation_out(value: domain::Relation) -> i32 {
    match value {
        domain::Relation::UserRoles => wire::Relation::UserRoles,
        domain::Relation::UserPermissions => wire::Relation::UserPermissions,
        domain::Relation::RolePermissions => wire::Relation::RolePermissions,
    }
    .into()
}

#[cfg(feature = "authorization")]
pub(in crate::server) fn assignment_key(
    value: Option<wire::AssignmentKey>
) -> Result<domain::AssignmentKey, Status> {
    let value =
        value.ok_or_else(|| Status::invalid_argument("key is required"))?;
    Ok(domain::AssignmentKey {
        relation: relation(value.relation)?,
        reference: required(value.reference, "reference")?,
    })
}

#[cfg(feature = "authorization")]
pub(in crate::server) fn members(
    values: Vec<String>
) -> Result<Vec<String>, Status> {
    let mut seen = std::collections::HashSet::new();
    for value in &values {
        if value.is_empty() || !seen.insert(value) {
            return Err(Status::invalid_argument(
                "members must be unique nonempty references",
            ));
        }
    }
    Ok(values)
}

#[cfg(feature = "authorization")]
pub(in crate::server) fn assignments(
    value: domain::Assignments
) -> Result<wire::Assignments, Status> {
    if value.revision.is_empty() || value.key.reference.is_empty() {
        return Err(Status::internal("provider returned invalid assignments"));
    }
    let checked = members(value.members).map_err(|_| {
        Status::internal("provider returned invalid assignment members")
    })?;
    Ok(wire::Assignments {
        key: Some(wire::AssignmentKey {
            relation: relation_out(value.key.relation),
            reference: value.key.reference,
        }),
        revision: value.revision,
        members: checked,
    })
}

#[cfg(feature = "authorization")]
pub(in crate::server) fn assignment_mutation(
    value: domain::Result<domain::Assignments>
) -> Result<wire::AssignmentMutationResult, Status> {
    use wire::assignment_mutation_result::Outcome;
    let outcome = match value {
        Ok(value) => Outcome::Assignments(assignments(value)?),
        Err(domain::ManagementError::Validation(values)) => {
            Outcome::Validation(validation(values)?)
        }
        Err(error) => return Err(status(error)),
    };
    Ok(wire::AssignmentMutationResult { outcome: Some(outcome) })
}
