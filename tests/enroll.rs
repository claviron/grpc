use super::{Credential, Enrollment};

#[test]
fn an_enrollment_names_its_credential_kind() {
    let password: Enrollment = serde_json::from_str(
        r#"{"credential":{"password":{"username":"ada","password":"secret"}},"csr_der":"AA=="}"#,
    )
    .unwrap();
    assert!(matches!(
        password.credential,
        Credential::Password { ref username, ref password }
            if username == "ada" && password == "secret"
    ));

    let token: Enrollment = serde_json::from_str(
        r#"{"credential":{"token":"invite"},"csr_der":"AA=="}"#,
    )
    .unwrap();
    assert!(
        matches!(token.credential, Credential::Token(ref token) if token == "invite")
    );

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
