use super::*;

#[tokio::test]
async fn issuance_fails_closed_without_hosting() {
    let service = MtlsService { state: AppState::standalone("mtls-test", ".") };
    let error = service
        .create_certificate(Request::new(CreateCertificateRequest {
            permissions: None,
            subject_uri: None,
            issuer: None,
            ca_path_len: None,
            kind: crate::proto::mtls::CertificateKind::Client as i32,
            common_name: "client.test".into(),
            aliases: vec![],
            validity_days: 1,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
}
