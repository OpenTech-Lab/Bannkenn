use super::*;
use crate::ebpf::events::ProcessTrustClass;

fn tracked_process(pid: u32, process_name: &str, exe_path: &str) -> TrackedProcess {
    TrackedProcess {
        pid,
        parent_pid: None,
        uid: None,
        gid: None,
        service_unit: None,
        first_seen_at: chrono::Utc::now(),
        trust_class: ProcessTrustClass::Unknown,
        process_name: process_name.to_string(),
        exe_path: exe_path.to_string(),
        command_line: exe_path.to_string(),
        parent_process_name: None,
        parent_command_line: None,
        container_runtime: None,
        container_id: None,
        open_paths: HashSet::from(["/srv/data/file.txt".to_string()]),
        protected: false,
    }
}

#[test]
fn lifecycle_diff_detects_exec_exit_and_reexec() {
    let previous = HashMap::from([
        (
            10,
            ProcessIdentity {
                process_name: "bash".to_string(),
                exe_path: "/usr/bin/bash".to_string(),
            },
        ),
        (
            20,
            ProcessIdentity {
                process_name: "python3".to_string(),
                exe_path: "/usr/bin/python3".to_string(),
            },
        ),
    ]);
    let current = HashMap::from([
        (20, tracked_process(20, "python3", "/usr/bin/python3.12")),
        (30, tracked_process(30, "ransom", "/tmp/ransom")),
    ]);

    let events = diff_lifecycle_events(&previous, &current);
    assert!(events.contains(&LifecycleEvent::Exec {
        pid: 20,
        process_name: "python3".to_string(),
        exe_path: "/usr/bin/python3.12".to_string(),
    }));
    assert!(events.contains(&LifecycleEvent::Exec {
        pid: 30,
        process_name: "ransom".to_string(),
        exe_path: "/tmp/ransom".to_string(),
    }));
    assert!(events.contains(&LifecycleEvent::Exit {
        pid: 10,
        process_name: "bash".to_string(),
    }));
}

#[test]
fn allowlist_matching_is_case_insensitive() {
    assert!(matches_allowlist(
        "/usr/local/bin/BannKenn-Agent",
        &["bannkenn-agent".to_string()]
    ));
    assert!(!matches_allowlist(
        "/usr/bin/python3",
        &["systemd".to_string()]
    ));
}

#[test]
fn container_context_detects_runtime_and_id_from_cgroup_lines() {
    let metadata = read_cgroup_metadata_from_str(
        "0::/system.slice/docker-0123456789abcdef0123456789abcdef.scope\n",
    );
    assert_eq!(metadata.container_runtime.as_deref(), Some("docker"));
    assert_eq!(
        metadata.container_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn container_context_detects_kubernetes_containerd_paths() {
    let metadata = read_cgroup_metadata_from_str(
        "0::/kubepods/besteffort/pod1234/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    );
    assert_eq!(metadata.container_runtime.as_deref(), Some("kubernetes"));
    assert_eq!(
        metadata.container_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn container_context_detects_crio_runtime_from_scope_prefix() {
    let metadata = read_cgroup_metadata_from_str(
        "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/crio-0123456789abcdef0123456789abcdef.scope\n",
    );
    assert_eq!(metadata.container_runtime.as_deref(), Some("crio"));
    assert_eq!(
        metadata.container_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn cgroup_metadata_extracts_service_unit() {
    let metadata = read_cgroup_metadata_from_str("0::/system.slice/fwupd.service\n");
    assert_eq!(metadata.service_unit.as_deref(), Some("fwupd.service"));
}

#[test]
fn process_profiles_keep_first_seen_across_refreshes() {
    let config = ContainmentConfig {
        watch_paths: vec!["/srv/data".to_string()],
        ..ContainmentConfig::default()
    };
    let mut tracker = ProcessLifecycleTracker::new(&config);
    let mut first = tracked_process(10, "fwupd", "/usr/libexec/fwupd/fwupd");
    first.service_unit = Some("fwupd.service".to_string());
    let first_seen = chrono::Utc::now();

    let mut initial = HashMap::from([(10, first)]);
    tracker.apply_profile_metadata(&mut initial, first_seen);

    let initial_seen_at = initial.get(&10).expect("tracked process").first_seen_at;

    let mut second = tracked_process(11, "fwupd", "/usr/libexec/fwupd/fwupd");
    second.service_unit = Some("fwupd.service".to_string());
    let mut next = HashMap::from([(11, second)]);
    tracker.apply_profile_metadata(&mut next, first_seen + chrono::Duration::minutes(5));

    assert_eq!(
        next.get(&11).expect("tracked process").first_seen_at,
        initial_seen_at
    );
}

#[test]
fn classify_process_trust_marks_temp_exec_as_suspicious() {
    let process = tracked_process(44, "payload", "/tmp/payload");
    assert_eq!(
        classify_process_trust(&process),
        ProcessTrustClass::Suspicious
    );
}

#[test]
fn classify_process_trust_marks_package_managed_service_as_trusted() {
    let mut process = tracked_process(55, "fwupd", "/usr/libexec/fwupd/fwupd");
    process.uid = Some(0);
    process.parent_process_name = Some("systemd".to_string());
    process.service_unit = Some("fwupd.service".to_string());

    assert_eq!(
        classify_process_trust(&process),
        ProcessTrustClass::TrustedPackageManaged
    );
}

#[test]
fn status_metadata_reads_parent_uid_and_gid() {
    let path = std::env::temp_dir().join(format!("bannkenn-status-{}", uuid::Uuid::new_v4()));
    fs::write(
        &path,
        "Name:\tpython3\nPPid:\t77\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n",
    )
    .unwrap();

    let metadata = read_status_metadata(path.clone());

    assert_eq!(metadata.parent_pid, Some(77));
    assert_eq!(metadata.uid, Some(1000));
    assert_eq!(metadata.gid, Some(1001));

    let _ = fs::remove_file(path);
}

fn read_cgroup_metadata_from_str(content: &str) -> CgroupMetadata {
    let path = std::env::temp_dir().join(format!("bannkenn-cgroup-{}", uuid::Uuid::new_v4()));
    fs::write(&path, content).unwrap();
    let result = read_cgroup_metadata(path.clone());
    let _ = fs::remove_file(path);
    result
}
