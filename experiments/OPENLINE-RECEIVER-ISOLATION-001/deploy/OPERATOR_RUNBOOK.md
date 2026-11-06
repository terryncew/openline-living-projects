# OpenLine Production Isolation — Operator Runbook (`M7`)

## 1. Architecture Overview

OpenLine Production Isolation enforces a three-tier privilege separation boundary on Linux 5.6+ systemd hosts:

1. **Receiver (`ol-recv-p1`)**: Sole owner of `/var/lib/openline/projects/p1` (`accepted.git`, `project.sqlite`, `effects.sqlite`, `promotion/`, `incidents/`, `keys/receiver.key`). Listens on `/run/openline/p1/worker.sock` and `/run/openline/p1/control.sock`. Never stores `owner.key`.
2. **Untrusted Workers (`ol-work-alice`, `ol-work-bob`)**: Connect only to `/run/openline/p1/worker.sock`. Receive byte-only snapshots (`assignment.prepare` + `snapshot.chunk`) and submit bounded `files[]` arrays (`proposal.submit`). Have zero filesystem access to `/var/lib/openline/projects/p1` or `/run/openline/p1/control.sock`.
3. **Unprivileged Validator (`ol-validate-p1`)**: Executes candidate validation against a plain file copy (`merged/` without `.git`) and read-only SQLite snapshots (`project_snapshot.sqlite`, `effects_snapshot.sqlite`) inside `/var/lib/openline/validation-spool/job-<uuid>` with `PrivateNetwork=yes`, `RestrictAddressFamilies=`, and `InaccessiblePaths=/var/lib/openline/projects /run/openline`.

---

## 2. Host Provisioning & Installation

```bash
sudo bash experiments/OPENLINE-RECEIVER-ISOLATION-001/deploy/provision_host.sh
sudo cp experiments/OPENLINE-RECEIVER-ISOLATION-001/deploy/openline-receiver-p1.service /etc/systemd/system/
sudo cp experiments/OPENLINE-RECEIVER-ISOLATION-001/deploy/openline-validate-p1.service /etc/systemd/system/
sudo cp experiments/OPENLINE-RECEIVER-ISOLATION-001/deploy/openline-validate-p1.path /etc/systemd/system/
sudo cp experiments/OPENLINE-RECEIVER-ISOLATION-001/deploy/openline-worker@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openline-receiver-p1.service openline-validate-p1.path
```

---

## 3. Emergency Kill Switch (`STOP` / `CLEAR`)

`control.sock` is serviced on a dedicated priority listener thread. Issuing `control.stop` immediately records `KILL_SWITCH_STOPPED` in `project.sqlite` and sends `SIGKILL` to any active validator process group within `<50ms`:

- **Pre-STOP authority**: Permanently dead (`old_authority_dead`), even after a subsequent `control.clear`.
- **Post-STOP override**: Requires an explicit owner-signed `post_stop_grant` bound to the current `(epoch, stop_seq)`.

---

## 4. Crash Recovery & `HOLD_RECONCILIATION` Forensic Triage

On startup, `OpenLineReceiverService.reconcile_startup()` automatically inspects `assignment_standing`, `promotion/task-*/state.json`, and `receipt_outbox`:

- **Pre-CAS interruption (`CUT-01`, `CUT-02`)**: Voids unapplied `PENDING_CAS` reservation (`CAS_ABORTED_PRE_REF`) and leaves `accepted.git` untouched.
- **Post-CAS / Pre-Settlement interruption (`CUT-03`)**: Detects `accepted == target_head`, completes `resolve_repair`, enqueues the signed `ACCEPTED` receipt in `receipt_outbox`, and flushes it to `incidents/`.
- **Post-Settlement / Pre-File or Lost-Response interruption (`CUT-04`, `CUT-06`)**: Flushes `receipt_outbox` to `incidents/<incident_id>.json` and replays the stored `openline.ipc.response.v1` envelope (`replayed=True`) when the client retries the same `request_id`.
- **Diverged Git Ref (`CUT-05`)**: If `refs/heads/accepted` is neither `expected_head` nor `target_head` during `PENDING_CAS`, the receiver transitions the assignment and project to `HOLD_RECONCILIATION`, preserves `commit_seq` and all forensic fields, and refuses further promotions until an operator inspects `git log` and `events`.

---

## 5. Consistent Online Backup, Restore & Key Rotation

Run the automated operational rehearsal at any time:

```bash
python3 experiments/OPENLINE-RECEIVER-ISOLATION-001/deploy/backup_restore_rehearsal.py
```
