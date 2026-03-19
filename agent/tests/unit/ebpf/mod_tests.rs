use super::*;
use crate::config::ContainmentConfig;
use crate::ebpf::events::{
    BehaviorLevel, RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY, RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXEC,
};
use crate::ebpf::lifecycle::{LifecycleSnapshot, TrackedProcess};

#[tokio::test]
async fn simulated_mass_rename_triggers_score_above_suspicious_threshold() {
    let root = std::env::temp_dir().join(format!("bannkenn-phase1-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();

    let mut open_files = Vec::new();
    for idx in 0..8 {
        let path = root.join(format!("file-{}.txt", idx));
        fs::write(&path, format!("payload-{}", idx)).unwrap();
    }

    let mut config = ContainmentConfig {
        enabled: true,
        watch_paths: vec![root.display().to_string()],
        ..ContainmentConfig::default()
    };
    config
        .protected_pid_allowlist
        .retain(|entry| entry != "bannkenn-agent");
    let mut sensor = SensorManager::from_config(&config).expect("sensor should be enabled");
    assert!(
        sensor.poll_once().await.unwrap().is_empty(),
        "baseline poll"
    );

    for idx in 0..8 {
        let from = root.join(format!("file-{}.txt", idx));
        open_files.push(fs::File::open(&from).unwrap());
        let to = root.join(format!("file-{}.locked", idx));
        fs::rename(&from, &to).unwrap();
    }

    let events = sensor.poll_once().await.unwrap();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert!(event.file_ops.renamed >= 8);
    assert!(event.score > 30);
    assert_eq!(event.level, BehaviorLevel::Suspicious);
    assert_eq!(event.pid, Some(std::process::id()));

    drop(open_files);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn lifecycle_ring_events_are_translated_without_duplicate_pid_entries() {
    let mut events = vec![LifecycleEvent::Exec {
        pid: 44,
        process_name: "python3".to_string(),
        exe_path: "/usr/bin/python3".to_string(),
    }];
    let raw = RawBehaviorRingEvent {
        pid: 44,
        event_kind: RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXEC,
        bytes_written: 0,
        created: 0,
        modified: 0,
        renamed: 0,
        deleted: 0,
        protected_path_touched: 0,
        path_len: 0,
        process_name_len: 7,
        path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
        process_name: [0; crate::ebpf::events::RAW_BEHAVIOR_PROCESS_CAPACITY],
    };
    let mut raw = raw;
    raw.process_name[..7].copy_from_slice(b"python3");

    merge_lifecycle_events(
        &mut events,
        raw_ring_event_to_lifecycle_event(raw).into_iter(),
    );
    assert_eq!(events.len(), 1);
}

#[test]
fn file_activity_ring_events_ignore_lifecycle_translation() {
    let raw = RawBehaviorRingEvent {
        pid: 7,
        event_kind: RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY,
        bytes_written: 2048,
        created: 0,
        modified: 1,
        renamed: 0,
        deleted: 0,
        protected_path_touched: 1,
        path_len: 13,
        process_name_len: 7,
        path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
        process_name: [0; crate::ebpf::events::RAW_BEHAVIOR_PROCESS_CAPACITY],
    };
    let mut raw = raw;
    raw.path[..13].copy_from_slice(b"/srv/data.txt");
    raw.process_name[..7].copy_from_slice(b"python3");

    assert!(raw_ring_event_to_lifecycle_event(raw).is_none());
    let batch = raw_ring_event_to_batch(raw, &[PathBuf::from("/srv")], 1000).expect("batch");
    assert_eq!(batch.bytes_written, 2048);
    assert_eq!(
        batch.protected_paths_touched,
        vec!["/srv/data.txt".to_string()]
    );
}

#[tokio::test]
async fn recent_temp_write_followed_by_exec_emits_trigger_event() {
    let root = std::env::temp_dir().join(format!("bannkenn-exec-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();

    let config = ContainmentConfig {
        enabled: true,
        watch_paths: vec![root.display().to_string()],
        ..ContainmentConfig::default()
    };
    let mut sensor = SensorManager::from_config(&config).expect("sensor should be enabled");
    sensor.recent_temp_writes.insert(
        "/tmp/payload".to_string(),
        RecentTempWrite {
            recorded_at: Instant::now(),
            watched_root: "/tmp".to_string(),
        },
    );
    let lifecycle = LifecycleSnapshot {
        processes: vec![TrackedProcess {
            pid: 77,
            process_name: "cron".to_string(),
            exe_path: "/tmp/payload".to_string(),
            command_line: "/tmp/payload --run".to_string(),
            parent_process_name: Some("systemd".to_string()),
            parent_command_line: Some("systemd".to_string()),
            container_runtime: None,
            container_id: None,
            open_paths: BTreeSet::new().into_iter().collect(),
            protected: false,
        }],
        events: vec![LifecycleEvent::Exec {
            pid: 77,
            process_name: "cron".to_string(),
            exe_path: "/tmp/payload".to_string(),
        }],
    };

    let events = sensor.build_temp_exec_events(&lifecycle);

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].level, BehaviorLevel::Suspicious);
    assert!(events[0]
        .reasons
        .iter()
        .any(|reason| reason == "temp write followed by execve"));
    assert!(events[0]
        .reasons
        .iter()
        .any(|reason| reason == "process name/executable mismatch"));

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn ringbuf_exec_events_fall_back_to_tracked_process_exe_path() {
    let root =
        std::env::temp_dir().join(format!("bannkenn-exec-fallback-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();

    let config = ContainmentConfig {
        enabled: true,
        watch_paths: vec![root.display().to_string()],
        ..ContainmentConfig::default()
    };
    let mut sensor = SensorManager::from_config(&config).expect("sensor should be enabled");
    sensor.recent_temp_writes.insert(
        "/tmp/payload".to_string(),
        RecentTempWrite {
            recorded_at: Instant::now(),
            watched_root: "/tmp".to_string(),
        },
    );
    let lifecycle = LifecycleSnapshot {
        processes: vec![TrackedProcess {
            pid: 88,
            process_name: "payload".to_string(),
            exe_path: "/tmp/payload".to_string(),
            command_line: "/tmp/payload --run".to_string(),
            parent_process_name: Some("systemd".to_string()),
            parent_command_line: Some("systemd".to_string()),
            container_runtime: None,
            container_id: None,
            open_paths: std::collections::HashSet::new(),
            protected: false,
        }],
        events: vec![LifecycleEvent::Exec {
            pid: 88,
            process_name: "payload".to_string(),
            exe_path: "payload".to_string(),
        }],
    };

    let events = sensor.build_temp_exec_events(&lifecycle);

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].touched_paths, vec!["/tmp/payload".to_string()]);

    let _ = fs::remove_dir_all(root);
}
