use super::*;

#[test]
fn runtime_clock_mapping_preserves_subseconds() {
    let elapsed = Duration::new(12, 34);
    assert_eq!(
        timestamp(SystemTime::UNIX_EPOCH + elapsed),
        Some(prost_types::Timestamp { seconds: 12, nanos: 34 })
    );
    assert_eq!(
        duration(elapsed),
        Some(prost_types::Duration { seconds: 12, nanos: 34 })
    );
    assert_eq!(
        timestamp(SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
        None
    );
}

#[test]
fn info_wire_preserves_absence_and_explicit_zero() {
    use prost::Message;
    let info = InfoResponse {
        workers_desired: Some(0),
        responding_process: Some(ProcessInfo {
            run_mode: RunMode::Worker as i32,
            worker_id: Some(1),
            ..Default::default()
        }),
        ..Default::default()
    };
    let decoded =
        InfoResponse::decode(info.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded.workers_desired, Some(0));
    assert_eq!(decoded.workers_running, None);
    assert_eq!(decoded.started_at, None);
    assert_eq!(decoded.uptime, None);
    assert_eq!(decoded.reload_revision, None);
    assert_eq!(decoded.responding_process.unwrap().worker_id, Some(1));
}

#[test]
fn master_runtime_is_not_the_responding_workers_clock() {
    let worker = ProcessInfo {
        started_at: timestamp(SystemTime::UNIX_EPOCH + Duration::from_secs(90)),
        uptime: duration(Duration::from_secs(10)),
        reload_revision: 1,
        ..Default::default()
    };
    let mut info =
        InfoResponse { responding_process: Some(worker), ..Default::default() };
    apply_master_runtime(
        &mut info,
        MasterRuntimeSnapshot {
            started_at_unix_ms: 50_123,
            uptime: Duration::from_millis(49_877),
            reload_revision: 3,
        },
    );
    assert_eq!(
        info.started_at,
        Some(prost_types::Timestamp { seconds: 50, nanos: 123_000_000 })
    );
    assert_eq!(
        info.uptime,
        Some(prost_types::Duration { seconds: 49, nanos: 877_000_000 })
    );
    assert_eq!(info.reload_revision, Some(3));
    assert_eq!(info.responding_process, Some(worker));
}
