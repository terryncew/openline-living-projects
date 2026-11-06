#!/usr/bin/env bash
# Reproducible Disposable-VM Containment Qualification Harness
# NEVER substitutes a Linux namespace simulation for real KVM/libvirt hardware virtualization.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")" && pwd)"
ASTRA_VM_ROOT="$(cd "$PKG_DIR/../.." && pwd)"

missing=()
for dev in /dev/kvm /dev/net/tun; do
  [ -e "$dev" ] || missing+=("device:$dev")
done
for cmd in qemu-system-x86_64 virsh nft cloud-localds; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("cmd:$cmd")
done
if [ "$(id -u)" -ne 0 ]; then
  missing+=("privilege:root_required_for_libvirt_and_nftables(current_uid=$(id -u))")
fi

if [ "${#missing[@]}" -gt 0 ]; then
  python3 -c '
import json, platform, sys
print(json.dumps({
    "status": "PREFLIGHT_BLOCKED",
    "guest_root_containment": "NOT TESTED",
    "namespace_simulation_substituted": False,
    "kernel": platform.release(),
    "missing_prerequisites": sys.argv[1:],
    "package_dir": sys.argv[1] if False else "'"$PKG_DIR"'",
}, indent=2))
' "${missing[@]}"
  exit 0
fi

echo "All KVM/libvirt/nftables prerequisites present. Auditing domain XML before launch..."
python3 -c "
import sys
sys.path.insert(0, '$ASTRA_VM_ROOT/adapter')
from pathlib import Path
from vm_profile import audit_domain
res = audit_domain(
    Path('$PKG_DIR/worker.xml').read_text(),
    '/var/lib/libvirt/images/openline-worker-test.qcow2',
    '/var/lib/libvirt/images/openline-worker-seed.iso',
)
print('Domain XML audit:', res)
"
echo "Ready for operator-authorized disposable guest launch using $PKG_DIR/firewall.nft, $PKG_DIR/network.xml, and $PKG_DIR/worker.xml."
