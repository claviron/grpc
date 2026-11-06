use super::*;

#[cfg(feature = "registration")]
#[tokio::test]
async fn registration_persists_only_public_material_and_reuses_the_same_device()
{
    use std::{any::Any, borrow::Cow, num::NonZeroU32};

    use claviron::auth::Authenticated;
    use claviron::ssl::{Organization, generators};

    struct Operator;

    impl Authenticated for Operator {
        fn auth_subject(&self) -> Cow<'_, str> {
            "operator".into()
        }

        fn auth_identifier(&self) -> &str {
            "operator"
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("fixtures/certificates.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let store = HostingStore::sqlite(pool);
    MtlsManager::new(store.clone(), None, None)
        .create_root_ca(CreateRootCaRequest {
            common_name: "root.test".into(),
            validity_days: 30,
            ..Default::default()
        })
        .await
        .unwrap();
    let authority =
        CertAuthority::from_issuer(&store, "root.test").await.unwrap();
    let root_pem = claviron::ssl::formatters::certificate_chain_to_pem(
        authority.roots()[0].as_ref(),
    )
    .unwrap();
    let manager =
        MtlsManager::new(store.clone(), None, Some(Arc::new(authority)));
    let request = || {
        let key = generators::generate_private_key().unwrap();
        generators::generate_server_csr(
            &key,
            &"request.test".parse().unwrap(),
            Vec::new(),
            &Organization::default(),
        )
        .unwrap()
        .der()
        .as_ref()
        .to_vec()
    };
    let csr = request();
    let user = || crate::registration::GrpcUser::new(Arc::new(Operator));
    let validity = NonZeroU32::new(1).unwrap();
    let chain =
        manager.register_client(user(), csr.clone(), validity).await.unwrap();
    assert_eq!(chain.authority_certificate_pem, root_pem);
    assert!(!chain.certificate_chain_pem.contains(&root_pem));
    assert_eq!(
        manager.register_client(user(), csr, validity).await.unwrap(),
        chain
    );
    let stored =
        store.certificate_by_cn("operator").await.unwrap().unwrap().certificate;
    assert!(stored.key_der.is_empty());
    let rejected =
        manager.register_client(user(), request(), validity).await.unwrap_err();
    assert_eq!(rejected.code(), tonic::Code::AlreadyExists);
}

#[tokio::test]
async fn file_authority_persists_public_issuer_hierarchy_without_private_keys()
{
    use claviron::ssl::generators;

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("fixtures/certificates.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let store = HostingStore::sqlite(pool);
    let root_key = generators::generate_ca_key().unwrap();
    let root = generators::generate_ca_cert(
        &"Root CA".parse().unwrap(),
        &root_key,
        30,
        &Default::default(),
    )
    .unwrap();
    let key = generators::generate_ca_key().unwrap();
    let ca = generators::generate_intermediate_ca_cert(
        &key,
        root.as_ref(),
        &root_key,
        &"Intermediate CA".parse().unwrap(),
        7,
        &Default::default(),
        Some(0),
    )
    .unwrap();
    let authority = CertAuthority::new("authority.pem".into(), vec![ca, root]);
    let issuer = register_file_issuer(&store, &authority).await.unwrap();
    let repeated = register_file_issuer(&store, &authority).await.unwrap();
    assert_eq!(issuer.issuer_id(), repeated.issuer_id());
    let root = store.issuer_by_name("Root CA").await.unwrap().unwrap();
    let ca = store
        .certificate_by_cn("Intermediate CA")
        .await
        .unwrap()
        .unwrap()
        .certificate;
    assert_eq!(ca.issuer_id, Some(root.id));
    assert!(ca.key_der.is_empty());
    let stored_root =
        store.certificate_by_cn("Root CA").await.unwrap().unwrap().certificate;
    assert!(stored_root.key_der.is_empty());
    assert!(CertSigner::from_issuer(&store, "Intermediate CA").await.is_err());
}

#[test]
fn issuance_input_requires_explicit_validity_and_exact_client_names() {
    let request = |name: &str, days| CreateCertificateRequest {
        permissions: None,
        subject_uri: None,
        issuer: None,
        ca_path_len: None,
        kind: crate::proto::mtls::CertificateKind::Client as i32,
        common_name: name.into(),
        aliases: vec![
            "client.test".into(),
            "alias.test".into(),
            "alias.test".into(),
        ],
        validity_days: days,
    };
    assert!(input(request("client.test", 0)).is_err());
    assert!(input(request("client.test", u32::MAX)).is_err());
    assert!(input(request("*.test", 1)).is_err());
    let IssuanceRequest { name, aliases, .. } =
        input(request("client.test", 1)).unwrap();
    assert_eq!(name.as_str(), "client.test");
    assert_eq!(aliases, ["client.test", "alias.test"]);
}

#[tokio::test]
async fn ca_server_and_client_material_stays_in_database() {
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
    let manager = MtlsManager::new(store.clone(), Some(1), None);
    let root = manager
        .create_root_ca(CreateRootCaRequest {
            common_name: "root.test".into(),
            validity_days: 30,
            organization: None,
            country: None,
        })
        .await
        .unwrap();
    assert_eq!(root.issuer_id, None);
    let issuer = store.issuer_by_name("root.test").await.unwrap().unwrap();
    let authority =
        CertAuthority::from_issuer(&store, "root.test").await.unwrap();
    let configured = MtlsManager::new(
        store.clone(),
        Some(1),
        Some(Arc::new(authority.clone())),
    );
    let default_client = configured
        .create_certificate(CreateCertificateRequest {
            permissions: None,
            subject_uri: None,
            issuer: None,
            common_name: "default-client.test".into(),
            aliases: vec![],
            validity_days: 1,
            kind: crate::proto::mtls::CertificateKind::Client as i32,
            ca_path_len: None,
        })
        .await
        .unwrap();
    assert_eq!(default_client.issuer_id, Some(issuer.id));
    let mut catalog = PermissionCatalog::new();
    catalog.register::<crate::permission::GrpcAccess>().unwrap();
    let scoped_manager = configured.with_permissions(Arc::new(catalog));
    let scoped = scoped_manager
        .create_certificate(CreateCertificateRequest {
            common_name: "scoped-client.test".into(),
            aliases: vec![],
            validity_days: 1,
            kind: crate::proto::mtls::CertificateKind::Client as i32,
            issuer: None,
            ca_path_len: None,
            subject_uri: None,
            permissions: Some(crate::proto::mtls::CertificatePermissions {
                names: vec!["grpc.access".into(), "grpc.access".into()],
            }),
        })
        .await
        .unwrap();
    assert_eq!(scoped.permissions.unwrap().names, ["grpc.access"]);
    let renewed = scoped_manager
        .renew_certificate(RenewCertificateRequest {
            common_name: "scoped-client.test".into(),
            validity_days: 1,
        })
        .await
        .unwrap();
    assert_eq!(renewed.permissions.unwrap().names, ["grpc.access"]);
    let removed =
        scoped_manager.with_permissions(Arc::new(PermissionCatalog::new()));
    assert_eq!(
        removed
            .renew_certificate(RenewCertificateRequest {
                common_name: "scoped-client.test".into(),
                validity_days: 1,
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    for (kind, name, server) in [
        (CertificateKind::Client, "client.test", None),
        (CertificateKind::Server, "server.test", Some(1)),
        (CertificateKind::Ca, "intermediate.test", None),
    ] {
        let info = manager
            .create_certificate(CreateCertificateRequest {
                permissions: None,
                subject_uri: (kind == CertificateKind::Client).then(|| {
                    "urn:uuid:00000000-0000-4000-8000-000000000007".into()
                }),
                issuer: Some("root.test".into()),
                common_name: name.into(),
                aliases: if kind == CertificateKind::Ca {
                    vec![]
                } else {
                    vec!["alternate.test".into()]
                },
                validity_days: 1,
                kind: match kind {
                    CertificateKind::Server => {
                        crate::proto::mtls::CertificateKind::Server as i32
                    }
                    CertificateKind::Client => {
                        crate::proto::mtls::CertificateKind::Client as i32
                    }
                    CertificateKind::Ca => {
                        crate::proto::mtls::CertificateKind::Ca as i32
                    }
                },
                ca_path_len: (kind == CertificateKind::Ca).then_some(0),
            })
            .await
            .unwrap();
        assert_eq!(info.issuer_id, Some(issuer.id));
        assert_eq!(
            info.aliases,
            if kind == CertificateKind::Ca {
                vec![]
            } else {
                vec!["alternate.test"]
            }
        );
        let saved = store.certificate_by_id(info.id).await.unwrap().unwrap();
        assert!(!saved.key_der.is_empty());
        assert_eq!(saved.kind, kind);
        let peer =
            claviron::ssl::peer::peer_identity(&saved.certs_der).unwrap();
        assert_eq!(
            peer.subject_uris.len(),
            usize::from(kind == CertificateKind::Client)
        );
        if kind == CertificateKind::Client {
            assert_eq!(
                *peer.subject_uris,
                ["urn:uuid:00000000-0000-4000-8000-000000000007"]
                    .map(Box::<str>::from)
            );
        }

        let renewed = manager
            .renew_certificate(RenewCertificateRequest {
                common_name: name.into(),
                validity_days: 2,
            })
            .await
            .unwrap();
        assert_eq!(renewed.id, info.id);
        assert_eq!(renewed.aliases, info.aliases);
        assert_eq!(renewed.issuer_id, info.issuer_id);
        let updated = store.certificate_by_id(info.id).await.unwrap().unwrap();
        assert_eq!(updated.key_der, saved.key_der);
        assert_ne!(updated.certs_der, saved.certs_der);
        let before = take_first_cert_from_der(&saved.certs_der).unwrap();
        let after = take_first_cert_from_der(&updated.certs_der).unwrap();
        assert_eq!(before.subject().as_raw(), after.subject().as_raw());
        assert_eq!(before.extensions(), after.extensions());
        let root_material =
            store.certificate_by_id(root.id).await.unwrap().unwrap();
        let signer =
            take_first_cert_from_der(&root_material.certs_der).unwrap();
        assert!(after.verify_signature(Some(signer.public_key())).is_ok());
        assert_eq!(
            store.servers_for_certificate(name).await.unwrap().len(),
            usize::from(server.is_some())
        );
    }
    let root_before = store.certificate_by_id(root.id).await.unwrap().unwrap();
    let renewed = manager
        .renew_certificate(RenewCertificateRequest {
            common_name: "root.test".into(),
            validity_days: 30,
        })
        .await
        .unwrap();
    assert_eq!(renewed.id, root.id);
    let root_after = store.certificate_by_id(root.id).await.unwrap().unwrap();
    assert_eq!(root_before.key_der, root_after.key_der);
    assert!(matches!(
        store
            .renew_certificate_material(
                &root_before,
                root_before.certs_der.clone(),
                root_before.issued_at,
                root_before.expires_at
            )
            .await,
        Err(HostingError::Conflict(_))
    ));
    assert!(store.issuer_by_name("intermediate.test").await.unwrap().is_some());
    assert_eq!(store.acme_certificates(true, None).await.unwrap().len(), 0);
    let other = store.ensure_acme_issuer(1).await.unwrap();
    assert!(CertAuthority::from_issuer(&store, &other.name).await.is_err());
    let revoke =
        || RevokeCertificateRequest { common_name: "client.test".into() };
    let revoked = manager.revoke_certificate(revoke()).await.unwrap();
    assert!(!revoked.enabled);
    assert!(revoked.revoked_at.is_some());
    assert_eq!(
        manager.revoke_certificate(revoke()).await.unwrap().revoked_at,
        revoked.revoked_at
    );
    store.set_certificate_enabled("client.test", true).await.unwrap();
    let revoked_again = manager.revoke_certificate(revoke()).await.unwrap();
    assert!(!revoked_again.enabled);
    assert_eq!(revoked_again.revoked_at, revoked.revoked_at);
    assert_eq!(
        store
            .certificate_by_id(revoked.id)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .unwrap()
            .unix_timestamp(),
        revoked.revoked_at.unwrap().seconds
    );
    assert_eq!(
        manager
            .renew_certificate(RenewCertificateRequest {
                common_name: "client.test".into(),
                validity_days: 2
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        store
            .revoked_certificate_chains(
                OffsetDateTime::now_utc(),
                CertificateKind::Client
            )
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        manager
            .revoke_certificate(RevokeCertificateRequest {
                common_name: "missing.test".into()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    // Issuer ownership is irrelevant to revoking the stored identity locally.
    sqlx::query("UPDATE hosting_certificates SET issuer_id = ? WHERE cn = 'server.test'")
        .bind(other.id)
        .execute(&pool)
        .await
        .unwrap();
    let hosted = store.certificate_by_cn("server.test").await.unwrap().unwrap();
    let resolver = claviron::tls::CertResolver::new(
        std::collections::HashMap::new(),
        Arc::new(
            claviron::tls::pem::db_cert_to_certified_key(&hosted.certificate)
                .unwrap(),
        ),
    );
    let certificates =
        claviron::tls::CertificateManager::new(&store, &resolver);
    certificates.upsert(hosted).unwrap();
    assert!(resolver.contains("server.test"));
    assert!(resolver.contains("alternate.test"));
    for name in ["server.test", "root.test"] {
        let revoked = manager
            .revoke_certificate(RevokeCertificateRequest {
                common_name: name.into(),
            })
            .await
            .unwrap();
        assert!(!revoked.enabled);
        assert!(revoked.revoked_at.is_some());
    }
    certificates.upsert_cn("server.test").await.unwrap();
    assert!(!resolver.contains("server.test"));
    assert!(!resolver.contains("alternate.test"));
    assert_eq!(
        store
            .revoked_certificate_chains(
                OffsetDateTime::now_utc(),
                CertificateKind::Client
            )
            .await
            .unwrap()
            .len(),
        1
    );
    store.set_certificate_enabled("root.test", false).await.unwrap();
    assert!(CertAuthority::from_issuer(&store, "root.test").await.is_err());
    assert!(authority.validate_issuer(&store).await.is_err());
}

#[test]
fn issuance_identity_is_client_only_and_a_uri_not_a_hostname_alias() {
    let mut request = CreateCertificateRequest {
        permissions: None,
        common_name: "display.test".into(),
        validity_days: 1,
        kind: crate::proto::mtls::CertificateKind::Client as i32,
        subject_uri: Some(
            "urn:uuid:00000000-0000-4000-8000-000000000007".into(),
        ),
        ..Default::default()
    };
    let parsed = input(request.clone()).unwrap();
    assert_eq!(parsed.aliases, ["display.test"]);
    assert_eq!(
        parsed.subject_uri.unwrap().as_str(),
        request.subject_uri.as_deref().unwrap()
    );
    request.kind = crate::proto::mtls::CertificateKind::Server as i32;
    assert!(input(request.clone()).is_err());
    request.kind = crate::proto::mtls::CertificateKind::Client as i32;
    request.subject_uri = Some("not a URI".into());
    assert!(input(request).is_err());
}

#[tokio::test]
async fn permission_catalog_rejects_unknown_names_before_storage_or_signing() {
    use crate::proto::mtls::CertificatePermissions;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_lazy("sqlite::memory:")
        .unwrap();
    let manager = MtlsManager::new(HostingStore::sqlite(pool), None, None);
    let mut request = CreateCertificateRequest {
        common_name: "client.test".into(),
        aliases: vec![],
        validity_days: 1,
        kind: crate::proto::mtls::CertificateKind::Client as i32,
        issuer: None,
        ca_path_len: None,
        subject_uri: None,
        permissions: Some(CertificatePermissions {
            names: vec!["grpc.access".into()],
        }),
    };
    assert_eq!(
        manager.create_certificate(request.clone()).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    let mut catalog = PermissionCatalog::new();
    catalog.register::<crate::permission::GrpcAccess>().unwrap();
    let manager = manager.with_permissions(Arc::new(catalog));
    request
        .permissions
        .as_mut()
        .unwrap()
        .names
        .push("undefined.permission".into());
    let error = manager.create_certificate(request.clone()).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    request.permissions.as_mut().unwrap().names = vec!["bad permission".into()];
    assert_eq!(
        manager.create_certificate(request).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}
