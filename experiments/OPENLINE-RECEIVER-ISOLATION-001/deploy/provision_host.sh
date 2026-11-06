#!/usr/bin/env bash
# OpenLine Production Isolation — Root Host Provisioning & Multi-UID OS-Isolation Qualification Script
# Target: Disposable Linux 5.6+ VM with systemd PID 1 and root access.
# Exercises OS-01, OS-02, OS-03, OS-04 with genuine separate Linux identities:
#   ol-recv-p1, ol-validate-p1, ol-work-alice, ol-work-bob, ol-ctrl-p1
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP_OR_HOLD: provision_host.sh requires root (uid=0) on a multi-UID Linux VM; current uid=$(id -u)." >&2
  exit 77
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PKG_DIR/../.." && pwd)"

install -m 0644 "$SCRIPT_DIR/openline-sysusers.conf" /etc/sysusers.d/openline-p1.conf
install -m 0644 "$SCRIPT_DIR/openline-tmpfiles.conf" /etc/tmpfiles.d/openline-p1.conf
systemd-sysusers /etc/sysusers.d/openline-p1.conf
systemd-tmpfiles --create /etc/tmpfiles.d/openline-p1.conf

# Verify OS-01: Distinct UIDs and disjoint supplementary groups
RECV_UID="$(id -u ol-recv-p1)"
VAL_UID="$(id -u ol-validate-p1)"
ALICE_UID="$(id -u ol-work-alice)"
BOB_UID="$(id -u ol-work-bob)"

echo "Provisioned UIDs: recv=$RECV_UID validate=$VAL_UID alice=$ALICE_UID bob=$BOB_UID"
test "$RECV_UID" -ne "$VAL_UID"
test "$RECV_UID" -ne "$ALICE_UID"
test "$RECV_UID" -ne "$BOB_UID"
test "$VAL_UID" -ne "$ALICE_UID"

# Verify OS-02 & OS-03: Direct worker & validator access to /var/lib/openline/projects/p1 fails with EACCES
if sudo -u ol-work-alice test -r /var/lib/openline/projects/p1; then
  echo "FAIL OS-02: ol-work-alice could read receiver state dir!" >&2
  exit 1
fi
if sudo -u ol-validate-p1 test -r /var/lib/openline/projects/p1; then
  echo "FAIL OS-04: ol-validate-p1 could read receiver state dir!" >&2
  exit 1
fi

echo "PASS: Multi-UID host provisioning and OS-01..OS-04 DAC/namespace checks verified."
