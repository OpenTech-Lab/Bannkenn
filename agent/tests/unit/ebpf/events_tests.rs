use super::*;

#[test]
fn raw_ring_event_round_trips_strings() {
    let mut raw = RawBehaviorRingEvent {
        pid: 42,
        event_kind: RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY,
        bytes_written: 1024,
        created: 1,
        modified: 2,
        renamed: 3,
        deleted: 4,
        protected_path_touched: 1,
        path_len: 13,
        process_name_len: 7,
        path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
        process_name: [0; RAW_BEHAVIOR_PROCESS_CAPACITY],
    };
    raw.path[..13].copy_from_slice(b"/srv/data.txt");
    raw.process_name[..7].copy_from_slice(b"python3");

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &raw as *const RawBehaviorRingEvent as *const u8,
            size_of::<RawBehaviorRingEvent>(),
        )
    };
    let parsed = RawBehaviorRingEvent::from_bytes(bytes).expect("parse raw event");
    assert_eq!(parsed.path_string(), "/srv/data.txt");
    assert_eq!(parsed.process_name_string(), "python3");
    assert_eq!(parsed.file_ops().renamed, 3);
    assert_eq!(parsed.event_kind(), RawBehaviorEventKind::FileActivity);
}

#[test]
fn raw_ring_event_identifies_lifecycle_variants() {
    let raw = RawBehaviorRingEvent {
        pid: 99,
        event_kind: RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXIT,
        bytes_written: 0,
        created: 0,
        modified: 0,
        renamed: 0,
        deleted: 0,
        protected_path_touched: 0,
        path_len: 0,
        process_name_len: 0,
        path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
        process_name: [0; RAW_BEHAVIOR_PROCESS_CAPACITY],
    };

    assert!(raw.is_lifecycle_event());
    assert_eq!(raw.event_kind(), RawBehaviorEventKind::ProcessExit);
}
