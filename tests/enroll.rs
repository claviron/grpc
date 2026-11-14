use super::{Credential, Enrollment, is_device_label};

#[test]
fn an_enrollment_names_its_credential_kind() {
    let password: Enrollment = serde_json::from_str(
        r#"{"credential":{"password":{"username":"ada","password":"secret"}},"device":"bison-cli","csr_der":"AA=="}"#,
    )
    .unwrap();
    assert!(matches!(
        password.credential,
        Credential::Password { ref username, ref password }
            if username == "ada" && password == "secret"
    ));

    let token: Enrollment = serde_json::from_str(
        r#"{"credential":{"token":"invite"},"device":"bison-cli","csr_der":"AA=="}"#,
    )
    .unwrap();
    assert!(
        matches!(token.credential, Credential::Token(ref token) if token == "invite")
    );
    assert_eq!(token.device, "bison-cli");

    // A credential without its kind, or with a field of no kind, is refused.
    for refused in [
        r#"{"username":"ada","password":"secret","csr_der":"AA=="}"#,
        r#"{"credential":{"password":{"username":"ada","password":"secret","otp":"1"}},"csr_der":"AA=="}"#,
    ] {
        assert!(
            serde_json::from_str::<Enrollment>(refused).is_err(),
            "{refused}"
        );
    }
}

#[test]
fn a_device_label_is_one_dns_label() {
    for accepted in ["bison-cli", "iphone-app", "a", "x1"] {
        assert!(is_device_label(accepted), "{accepted}");
    }
    for refused in
        ["", "-cli", "cli-", "Bison", "bison.cli", "bison_cli", &"a".repeat(64)]
    {
        assert!(!is_device_label(refused), "{refused}");
    }
}

#[cfg(feature = "authorization")]
#[test]
fn a_request_stays_within_what_the_host_grants() {
    use claviron::auth::permission::PermissionCatalog;

    let mut catalog = PermissionCatalog::new();
    for name in ["deploy.release", "backup.restore"] {
        catalog.register_name(name).unwrap();
    }
    let bound = catalog.validate(["deploy.release"]).unwrap();
    let asked = |names: &[&str]| catalog.validate(names).unwrap();
    assert!(super::within(&asked(&[]), &bound));
    assert!(super::within(&asked(&["deploy.release"]), &bound));
    assert!(!super::within(
        &asked(&["deploy.release", "backup.restore"]),
        &bound
    ));
}
