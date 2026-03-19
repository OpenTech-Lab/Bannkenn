# tasks

## Done: Malware-specific trigger follow-up from 15.6 review

### Scope
- [x] Add temp-write followed by `execve` detection for the same temp path
- [x] Add process-name / executable-path mismatch weighting for masquerade detection
- [x] Add regression coverage for both new triggers
- [x] Re-review the remaining 15.6 gaps after implementation

### Notes
- Review correction: only the temp-path executable bonus was implemented; the rest of 15.6 was still missing.
- Current target: ship the two highest-signal triggers the existing lifecycle model can support cleanly without inventing network or persistence telemetry.
- Remaining 15.6 gaps after this patch: temp-write followed by outbound network, persistence after temp staging, and miner command-line / stratum detection are still open.

### Review
- Added recent temp-write tracking plus a synthetic `temp write followed by execve` behavior event in the eBPF sensor manager.
- Fixed the ringbuf exec path so temp-write→exec matching falls back to the tracked process `exe_path` when the raw eBPF exec event only carries a process name.
- Added process-name / executable-path mismatch weighting in the containment scorer.
- Verification: `cargo clippy --workspace -- -D warnings` passed.
- Verification: `cargo test --workspace` passed.

## Done: Workspace clippy hardening

### Scope
- [x] Run `cargo clippy --workspace -- -D warnings`
- [x] Fix every clippy warning without regressing behavior
- [x] Re-run clippy until it passes cleanly
- [x] Re-run relevant tests after the fixes

### Review
- Fixed the only workspace clippy failures in `server/src/feeds.rs` by switching stream error mapping to `std::io::Error::other`.
- Verification: `cargo clippy --workspace -- -D warnings` passed.
- Verification: `cargo test --workspace` passed.
- Note: Cargo reported a future-incompatibility notice for `sqlx-postgres v0.7.4`, but it does not fail clippy or tests today.

## Done: Container-aware detection follow-up from report review

### Scope
- [x] Extend tracked process metadata with container context and lightweight lineage hints
- [x] Use container context in the containment scorer to downgrade trusted containerized service temp activity
- [x] Add regression coverage for the `mariadbd`-inside-container style false-positive case
- [x] Re-review which report sections are still partial after the code change

### Notes
- Review correction: sections 15.5 and most of 15.6 were still missing; 15.2 and 15.4 were only partial.
- Goal: close the highest-priority gap called out in review without pretending Phase 2/3 work is complete.
- Remaining partial work after this patch: exec-chain/network correlation beyond temp-write→exec, persistence creation after temp staging, and miner-pattern detection are still not implemented.

## Done: Recreate follow-up tasks from `docs/05_Technical Investigation Report.md`

### Investigation-driven upgrade backlog
- [x] Recreate task inventory after manual cleanup of the old notes
- [x] Ship a concrete Detection v2 upgrade in the old containment scorer instead of leaving the report as documentation only
- [x] Reduce false positives for known benign temp-file activity described in the investigation report
- [x] Preserve genuinely suspicious temp-path behavior so the containment pipeline still escalates high-signal events
- [x] Add regression tests for the upgraded scorer behavior
- [x] Verify the agent crate still passes targeted tests after the scoring change

### Candidate follow-up tasks from the report
- [x] Package-manager awareness for `dpkg`/`apt` helper processes such as `depmod`, `cryptroot`, `update-initramfs`, and `ldconfig`
- [x] Known-runtime temp extraction downgrade for Java/OpenSearch/Solr JNI extraction patterns
- [x] Improve handling of `unknown process activity` so incomplete attribution is not treated as strong suspicion by itself
- [x] Add stronger malware-specific temp-path executable weighting
- [x] Add process-name / executable-path mismatch weighting for masquerade detection
- [ ] Evaluate future container-aware lineage enrichment beyond the current process snapshot model

### Current implementation target
- Upgrade the containment scorer to apply benign-context downgrades for package-maintenance helpers and known Java temp extraction patterns, and make `unknown process activity` require supporting suspicious signals before adding score.

### Review
- Implemented the upgrade in `agent/src/scorer.rs` rather than changing thresholds globally.
- Added temp-only benign-context downgrades for package-manager helpers and known Java/OpenSearch/Solr temp extraction behavior.
- Tightened `unknown process activity` so write-only unknown events no longer cross the suspicious threshold by bonus alone.
- Added a new high-signal boost for processes executing from `/tmp` or `/var/tmp`.
- Verification: `cargo test -p bannkenn-agent` passed after the change.
