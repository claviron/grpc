use claviron::ssl::generators;

use super::*;

#[tokio::test]
async fn transfer_roundtrip_keeps_key_optional_and_ca_unassigned() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("fixtures/certificates.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let store = HostingStore::sqlite(pool.clone());
    let manager = CertificateManager::new(store.clone(), Some(1));
    let key = generators::generate_ca_key().unwrap();
    let ca = generators::generate_ca_cert(
        &"root.test".parse().unwrap(),
        &key,
        30,
        &Default::default(),
    )
    .unwrap();
    let request = || ImportCertificateRequest {
        issuer: None,
        certificate_chain_pem: formatters::certificate_chain_to_pem(
            ca.as_ref(),
        )
        .unwrap(),
        private_key_pem: key.serialize_pem(),
    };
    let root = manager.import_certificate(request()).await.unwrap();
    assert_eq!(
        root.kind,
        crate::proto::certificates::CertificateKind::Ca as i32
    );
    assert!(root.issuer.is_none());
    assert_eq!(store.local_issuer_certificates().await.unwrap().len(), 1);
    assert!(
        store.servers_for_certificate("root.test").await.unwrap().is_empty()
    );
    assert_eq!(
        manager.import_certificate(request()).await.unwrap_err().code(),
        tonic::Code::AlreadyExists
    );
    for include_private_key in [false, true] {
        let exported = manager
            .export_certificate(ExportCertificateRequest {
                common_name: "root.test".into(),
                include_private_key,
            })
            .await
            .unwrap();
        assert_eq!(exported.private_key_pem.is_some(), include_private_key);
        assert_eq!(exported.certificate.unwrap().id, root.id);
        assert!(exported.certificate_chain_pem.contains("BEGIN CERTIFICATE"));
        if let Some(pem) = exported.private_key_pem {
            assert_eq!(pem, key.serialize_pem());
        }
    }
    let leaf_key = generators::generate_private_key().unwrap();
    let leaf = generators::generate_client_cert(
        &"client.test".parse().unwrap(),
        &leaf_key,
        ca.as_ref(),
        &key,
        1,
        &[] as &[String],
    )
    .unwrap();
    let client = manager
        .import_certificate(ImportCertificateRequest {
            issuer: None,
            certificate_chain_pem: formatters::certificate_chain_to_pem(
                &[ca.as_ref(), leaf.as_ref()].concat(),
            )
            .unwrap(),
            private_key_pem: leaf_key.serialize_pem(),
        })
        .await
        .unwrap();
    let duplicate = manager
        .import_certificate(ImportCertificateRequest {
            issuer: None,
            certificate_chain_pem: manager
                .export_certificate(ExportCertificateRequest {
                    common_name: "client.test".into(),
                    include_private_key: false,
                })
                .await
                .unwrap()
                .certificate_chain_pem,
            private_key_pem: leaf_key.serialize_pem(),
        })
        .await
        .unwrap_err();
    assert_eq!(duplicate.code(), tonic::Code::AlreadyExists);
    assert_eq!(
        client.kind,
        crate::proto::certificates::CertificateKind::Client as i32
    );
    assert_eq!(client.issuer.as_deref(), Some("root.test"));
    let exported = manager
        .export_certificate(ExportCertificateRequest {
            common_name: "client.test".into(),
            include_private_key: false,
        })
        .await
        .unwrap();
    assert_eq!(
        exported.certificate.unwrap().issuer.as_deref(),
        Some("root.test")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM hosting_certificate_server"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        manager
            .export_certificate(ExportCertificateRequest {
                common_name: "missing.test".into(),
                include_private_key: false
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
}

#[tokio::test]
async fn acme_import_is_rejected_but_existing_material_can_be_exported() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("fixtures/certificates.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let store = HostingStore::sqlite(pool.clone());
    let issuer = store.ensure_acme_issuer(1).await.unwrap();
    let manager = CertificateManager::new(store.clone(), Some(1));
    let ca_key = generators::generate_ca_key().unwrap();
    let ca = generators::generate_ca_cert(
        &"public-ca.test".parse().unwrap(),
        &ca_key,
        30,
        &Default::default(),
    )
    .unwrap();
    let key = generators::generate_private_key().unwrap();
    let server = generators::generate_leaf_cert(
        CertificateKind::Server,
        &"server.test".parse().unwrap(),
        &key,
        ca.as_ref(),
        &ca_key,
        1,
        &[] as &[String],
    )
    .unwrap();
    let fullchain = formatters::certificate_chain_to_pem(
        &[ca.as_ref(), server.as_ref()].concat(),
    )
    .unwrap();
    let request = |issuer| ImportCertificateRequest {
        issuer,
        certificate_chain_pem: fullchain.clone(),
        private_key_pem: key.serialize_pem(),
    };
    assert_eq!(
        manager.import_certificate(request(None)).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        manager
            .import_certificate(request(Some(issuer.name.clone())))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        manager
            .import_certificate(request(Some("missing".into())))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    assert!(store.certificate_by_cn("server.test").await.unwrap().is_none());
    assert!(store.local_issuer_certificates().await.unwrap().is_empty());
    assert!(store.acme_certificates(true, None).await.unwrap().is_empty());
    assert!(
        store.servers_for_certificate("server.test").await.unwrap().is_empty()
    );
    // Material from the separate issuance/local CLI path remains exportable.
    let ca_pem = formatters::certificate_chain_to_pem(ca.as_ref()).unwrap();
    let root_plan = transfer::plan_import(
        ca_pem.as_bytes(),
        ca_key.serialize_pem().as_bytes(),
        &[],
    )
    .unwrap();
    let plan = transfer::plan_import(
        fullchain.as_bytes(),
        key.serialize_pem().as_bytes(),
        &[transfer::IssuerCandidate {
            id: issuer.id,
            certs_der: root_plan.certs_der,
        }],
    )
    .unwrap();
    let aliases: Vec<String> = plan.aliases.into();
    store
        .insert_certificate(
            NewCertificate {
                kind: plan.kind,
                issuer_id: Some(issuer.id),
                cn: plan.common_name.into(),
                certs_der: plan.certs_der,
                key_der: plan.key_der,
                expires_at: plan.expires_at,
                issued_at: plan.issued_at,
                enabled: true,
            },
            &aliases,
            1,
        )
        .await
        .unwrap();
    let exported = manager
        .export_certificate(ExportCertificateRequest {
            common_name: "server.test".into(),
            include_private_key: false,
        })
        .await
        .unwrap();
    assert_eq!(
        exported.certificate.unwrap().issuer.as_deref(),
        Some(issuer.name.as_str())
    );
    assert!(exported.private_key_pem.is_none());
}
