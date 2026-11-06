use claviron::edge::HostConfig;
use tonic::Code;

use super::*;

fn resolver() -> Arc<VhostResolver> {
    let resolver = Arc::new(VhostResolver::default());
    for name in ["app.test", "empty.test", "default"] {
        resolver.upsert_host(
            name.parse().unwrap(),
            Arc::new(
                serde_yaml::from_str::<HostConfig>("root: public").unwrap(),
            ),
        );
    }
    resolver
        .upsert_alias("www.test".parse().unwrap(), "app.test".parse().unwrap())
        .unwrap();
    resolver
}

#[tokio::test]
async fn lists_runtime_hosts_and_aliases_without_a_hosting_store() {
    let state = AppState::standalone("alias-list-test", ".");
    let resolver = resolver();
    state.registry().insert(resolver.clone()).unwrap();
    let service = AliasService::new(state).unwrap();
    let hosts = service
        .list_hosting(Request::new(ListHostingRequest {
            enabled_vhosts_only: Some(true),
        }))
        .await
        .unwrap()
        .into_inner()
        .vhosts;
    let names: Vec<_> =
        hosts.iter().map(|h| h.vhost.as_ref().unwrap().name.as_str()).collect();
    assert_eq!(names, ["app.test", "default", "empty.test"]);
    assert_eq!(hosts[0].aliases[0].hostname, "www.test");
    assert_eq!(hosts[0].aliases[0].enabled, None);
    assert!(hosts[2].aliases.is_empty());
    assert!(hosts.iter().all(|h| h.servers.is_empty()));

    resolver
        .upsert_alias(
            "www.test".parse().unwrap(),
            "empty.test".parse().unwrap(),
        )
        .unwrap();
    let aliases = service
        .list_aliases(Request::new(ListAliasesRequest {
            vhost_name: Some("empty.test".into()),
            enabled_only: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .aliases;
    assert_eq!(aliases.len(), 1);
    assert_eq!(aliases[0].vhost_name, "empty.test");
    let err = service
        .list_aliases(Request::new(ListAliasesRequest {
            vhost_name: Some("missing.test".into()),
            enabled_only: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
}

#[test]
fn alias_target_must_be_canonical_and_must_not_shadow_a_host() {
    let resolver = resolver();
    assert!(
        validate_alias_target(&resolver, "new.test", "app.test", false).is_ok()
    );
    for target in ["missing.test", "www.test"] {
        assert_eq!(
            validate_alias_target(&resolver, "new.test", target, false)
                .unwrap_err()
                .code(),
            Code::NotFound
        );
    }
    assert_eq!(
        validate_alias_target(&resolver, "empty.test", "app.test", false)
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        validate_alias_target(&resolver, "www.test", "empty.test", false)
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert!(
        validate_alias_target(&resolver, "www.test", "empty.test", true)
            .is_ok()
    );
}

#[tokio::test]
async fn static_aliases_are_listed_and_rejected_before_any_database_access() {
    let resolver = resolver();
    resolver.upsert_host(
        "static.test".parse().unwrap(),
        Arc::new(
            serde_yaml::from_str::<HostConfig>(
                "root: public\naliases: [fixed.test]",
            )
            .unwrap(),
        ),
    );
    let state = AppState::standalone("static-alias-test", ".");
    state.registry().insert(resolver.clone()).unwrap();
    let service = AliasService::new(state).unwrap();
    // A previous mutation must not hide a config declaration from management.
    resolver.delete_alias(&"fixed.test".parse().unwrap());
    let response = service
        .list_hosting(Request::new(ListHostingRequest::default()))
        .await
        .unwrap()
        .into_inner();
    let hosted = response
        .vhosts
        .iter()
        .find(|h| h.vhost.as_ref().unwrap().name == "static.test")
        .unwrap();
    assert!(hosted.vhost.as_ref().unwrap().read_only);
    assert_eq!(hosted.aliases.len(), 1);
    assert_eq!(hosted.aliases[0].hostname, "fixed.test");
    assert!(hosted.aliases[0].read_only);
    assert_eq!(
        hosted.aliases[0].read_only_reason.as_deref(),
        Some(alias_read_only_reason())
    );
    let aliases = service
        .list_aliases(Request::new(ListAliasesRequest {
            vhost_name: Some("static.test".into()),
            enabled_only: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(aliases.aliases[0].alias.as_ref().unwrap(), &hosted.aliases[0]);

    let removed = service
        .remove_alias(Request::new(RemoveAliasRequest {
            hostname: "fixed.test".into(),
        }))
        .await
        .unwrap_err();
    let moved = service
        .replace_alias(Request::new(ReplaceAliasRequest {
            hostname: "fixed.test".into(),
            vhost_name: "app.test".into(),
        }))
        .await
        .unwrap_err();
    let added = service
        .add_alias(Request::new(AddAliasRequest {
            hostname: "fixed.test".into(),
            vhost_name: "static.test".into(),
        }))
        .await
        .unwrap_err();
    for error in [removed, moved, added] {
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(error.message(), alias_read_only_reason());
    }
    // The host is read-only; its dynamic alias namespace remains writable.
    assert!(
        validate_alias_target(&resolver, "new.test", "static.test", false)
            .is_ok()
    );
    let dynamic = response
        .vhosts
        .iter()
        .find(|h| h.vhost.as_ref().unwrap().name == "app.test")
        .unwrap();
    assert!(!dynamic.aliases[0].read_only);
    assert!(dynamic.aliases[0].read_only_reason.is_none());
}
