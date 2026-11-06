use prost::Message;

use crate::proto::{management, users};

#[test]
fn user_management_schema_round_trip_keeps_forms_and_capabilities() {
    let schema = users::ManagementSchema {
        resource: users::Resource::User.into(),
        revision: "schema-v1".into(),
        record_schema_json: br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#.to_vec(),
        create: None,
        update: Some(management::Form {
            data_schema_json:
                br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"label":{"type":"string"}}}"#
                    .to_vec(),
            ui_schema_json: Some(
                br##"{"type":"Control","scope":"#/properties/label"}"##
                    .to_vec(),
            ),
        }),
        operations: vec![
            users::Operation::Read.into(),
            users::Operation::Update.into(),
        ],
    };
    let decoded =
        users::ManagementSchema::decode(schema.encode_to_vec().as_slice())
            .unwrap();
    assert_eq!(decoded, schema);
    assert!(decoded.create.is_none());
    assert!(decoded.update.unwrap().ui_schema_json.is_some());
}

#[test]
fn user_management_update_round_trip_preserves_sparse_json_and_revisions() {
    let update = users::UpdateRecordRequest {
        key: Some(users::RecordKey {
            resource: users::Resource::User.into(),
            reference: "public-user".into(),
        }),
        revision: "record-v1".into(),
        schema_revision: "schema-v1".into(),
        changes_json: br#"{"birth_date":null,"enabled":false,"counter":18446744073709551615}"#.to_vec(),
    };
    let decoded =
        users::UpdateRecordRequest::decode(update.encode_to_vec().as_slice())
            .unwrap();
    assert_eq!(decoded, update);
}

#[test]
fn user_management_validation_is_distinct_from_committed_record() {
    let result = users::RecordMutationResult {
        outcome: Some(users::record_mutation_result::Outcome::Validation(
            management::ValidationFailure {
                violations: vec![management::FieldViolation {
                    path: "/email".into(),
                    code: "already_used".into(),
                    message: "This address is already assigned.".into(),
                }],
            },
        )),
    };
    let decoded =
        users::RecordMutationResult::decode(result.encode_to_vec().as_slice())
            .unwrap();
    assert_eq!(decoded, result);
    assert!(matches!(
        decoded.outcome,
        Some(users::record_mutation_result::Outcome::Validation(_))
    ));
}

#[test]
fn user_management_clear_assignments_round_trip_keeps_empty_set() {
    let replace = users::ReplaceAssignmentsRequest {
        key: Some(users::AssignmentKey {
            relation: users::Relation::UserRoles.into(),
            reference: "public-user".into(),
        }),
        revision: "assignments-v1".into(),
        members: vec![],
    };
    let decoded = users::ReplaceAssignmentsRequest::decode(
        replace.encode_to_vec().as_slice(),
    )
    .unwrap();
    assert_eq!(decoded, replace);
    assert!(decoded.members.is_empty());
}
