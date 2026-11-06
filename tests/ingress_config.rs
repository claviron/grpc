use super::GrpcConfig;

#[test]
fn absence_binds_nothing_and_retired_auth_switches_are_rejected() {
    let config = GrpcConfig::default();
    assert!(config.vhosts().is_empty());
    for retired in [
        "enabled: true",
        "host: management",
        "hosts: management",
        "mode: both",
        "require_client_auth: false",
        "dedicated: {}",
        "listener: {}",
        "request_timeout: 30s",
        "max_requests: 100",
    ] {
        assert!(serde_yaml::from_str::<GrpcConfig>(retired).is_err());
    }
}

#[test]
fn canonical_vhost_keys_can_be_declared_as_one_or_many() {
    for config in ["vhost: management", "vhosts: [management]"] {
        let config: GrpcConfig = serde_yaml::from_str(config).unwrap();
        assert_eq!(config.vhosts(), &["management".parse().unwrap()]);
    }
}
