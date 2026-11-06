use super::{ManagementTransport, ServiceAction, command_transport};

#[test]
fn management_cannot_stop_or_restart_its_own_transport() {
    for id in ["management", "public-tls", "public-quic"] {
        let owner = ManagementTransport(id.parse().unwrap());
        let name = format!("Listener:{id}");
        for action in [ServiceAction::Stop, ServiceAction::Restart] {
            let error =
                command_transport(Some(&owner), &name, action).err().unwrap();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        }
        for action in [ServiceAction::Start, ServiceAction::Reload] {
            assert!(command_transport(Some(&owner), &name, action).is_ok());
        }
    }
}

#[test]
fn management_can_control_other_transport_and_missing_ownership_fails_closed() {
    let owner = ManagementTransport("management".parse().unwrap());
    for action in [ServiceAction::Stop, ServiceAction::Restart] {
        assert!(
            command_transport(Some(&owner), "Listener:public-tls", action)
                .is_ok()
        );
        assert!(
            command_transport(None, "Listener:public-tls", action).is_err()
        );
    }
}
