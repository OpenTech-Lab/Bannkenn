# BannKenn vNext — Implementation Plan

## Deployment
- [x] Add eBPF build stage to Docker (linux-headers, clang, llvm)
- [x] Feature flags default: enabled=false, dry_run=true, fuse_enabled=false
- [x] Update installer for kernel version check (Linux 5.8+ required)
- [x] Rollback documentation

## Optional Deployment / Runtime Follow-Up
- [x] Teach `bannkenn-agent update` to fetch/install the matching `.bpf.o` release asset
- [x] Keep GitHub Releases + `sudo bannkenn-agent init` as the primary agent distribution path; no separate Dockerized agent package path is required
- [ ] Exercise real privileged eBPF attachment on a Linux host and document the exact runtime capability requirements
- [ ] Exercise real privileged cgroup/tc containment enforcement on a Linux host and document the exact runtime prerequisites/observed behavior

## tasks

## 2026-03-18 Agent Detail Log Navigation
- [x] Add offset-based pagination support to agent detail history endpoints for behavior events, containment history, containment actions, telemetry, and decisions
- [x] Update dashboard agent detail data loaders/types to fetch paged log slices while keeping summary cards/current state intact
- [x] Add a top-level tab switch between behavior logs and IP logs on `agents/{id}` and add pagination controls to each log/history block
- [x] Verify the dashboard build succeeds and record review notes/results here

## Review
- Added offset-based paginated responses for the agent detail history endpoints and updated the dashboard proxy/client types to consume them.
- `agents/{id}` now has paginated controls for operator actions, behavior events, containment history, telemetry events, and IP decisions, plus a top-level Behavior Logs / IP Logs tab switch.
- Verification: `cargo test -p bannkenn-server --test db_events --test db_behavior --test containment_actions` and `npm run build` in `dashboard/` both passed on 2026-03-18.
