"""Generate deliberately narrow libvirt assets; never start or reconfigure a host."""
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET

NAME = 'openline-worker-test'
BRIDGE = 'olvmt0'
HOST = '192.168.251.1'
GUEST = '192.168.251.2'

FORBIDDEN_ELEMENTS = frozenset({
    'filesystem',
    'hostdev',
    'channel',
    'redirdev',
    'smartcard',
    'tpm',
    'vsock',
    'shmem',
    'graphics',
    'serial',
    'parallel',
    'console',
    'audio',
    'sound',
    'backenddomain',
    'resource',
    'backingStore',
    'kernel',
    'initrd',
    'cmdline',
    'loader',
    'nvram',
    'bios',
    'init',
    'initarg',
    'memoryBacking',
    'iommu',
    'panic',
    'watchdog',
    'rng',
    'crypto',
    'script',
    'rom',
    'backend',
    'auth',
    'encryption',
    'iotune',
    'transient',
    'slices',
})


def domain(disk, seed):
    disk, seed = str(Path(disk).resolve()), str(Path(seed).resolve())
    root = ET.Element('domain', {'type': 'kvm'})
    ET.SubElement(root, 'name').text = NAME
    ET.SubElement(root, 'memory', {'unit': 'MiB'}).text = '1024'
    ET.SubElement(root, 'vcpu').text = '1'
    os_node = ET.SubElement(root, 'os')
    ET.SubElement(os_node, 'type', {'arch': 'x86_64', 'machine': 'q35'}).text = 'hvm'
    ET.SubElement(os_node, 'boot', {'dev': 'hd'})
    ET.SubElement(root, 'on_poweroff').text = 'destroy'
    ET.SubElement(root, 'on_reboot').text = 'restart'
    ET.SubElement(root, 'on_crash').text = 'destroy'
    devices = ET.SubElement(root, 'devices')
    for source, target, kind in [(disk, 'vda', 'disk'), (seed, 'sda', 'cdrom')]:
        d = ET.SubElement(devices, 'disk', {'type': 'file', 'device': kind})
        ET.SubElement(d, 'driver', {'name': 'qemu', 'type': 'qcow2' if kind == 'disk' else 'raw'})
        ET.SubElement(d, 'source', {'file': source})
        ET.SubElement(d, 'target', {'dev': target, 'bus': 'virtio' if kind == 'disk' else 'sata'})
        if kind == 'cdrom':
            ET.SubElement(d, 'readonly')
    net = ET.SubElement(devices, 'interface', {'type': 'network'})
    ET.SubElement(net, 'source', {'network': 'openline-isolated'})
    ET.SubElement(net, 'mac', {'address': '52:54:00:71:00:02'})
    ET.SubElement(net, 'model', {'type': 'virtio'})
    ET.SubElement(devices, 'controller', {'type': 'usb', 'model': 'none'})
    ET.SubElement(devices, 'memballoon', {'model': 'none'})
    # Deliberately no guest-agent/channel/console/shared-filesystem/host-device/QEMU args.
    return ET.tostring(root, encoding='unicode') + '\n'


def audit_domain(xml, disk, seed):
    root = ET.fromstring(xml)
    if root.tag != 'domain' or root.get('type') != 'kvm' or root.findtext('name') != NAME:
        raise ValueError('wrong domain')
    for e in root.iter():
        if e.tag in FORBIDDEN_ELEMENTS or '}' in e.tag or e.tag.startswith('qemu:'):
            raise ValueError('unapproved domain element: ' + e.tag)
    devices = root.find('devices')
    if devices is None:
        raise ValueError('missing devices')
    allowed = {'disk', 'interface', 'controller', 'memballoon', 'emulator', 'input', 'video'}
    for e in devices:
        if e.tag not in allowed:
            raise ValueError('unknown device: ' + e.tag)
    expected = {
        str(Path(disk).resolve()): ('disk', 'qcow2'),
        str(Path(seed).resolve()): ('cdrom', 'raw'),
    }
    disks = devices.findall('disk')
    if len(disks) != 2:
        raise ValueError('disk count')
    for d in disks:
        src = d.find('source')
        driver = d.find('driver')
        pair = expected.pop(src.get('file', ''), None) if src is not None else None
        if pair is None or d.get('type') != 'file' or d.get('device') != pair[0] or driver is None or driver.get('type') != pair[1]:
            raise ValueError('unapproved disk')
        if pair[0] == 'cdrom' and d.find('readonly') is None:
            raise ValueError('seed must be read only')
        if d.find('shareable') is not None:
            raise ValueError('shared disk')
    nets = devices.findall('interface')
    if (
        len(nets) != 1
        or nets[0].get('type') != 'network'
        or nets[0].find('source') is None
        or nets[0].find('source').get('network') != 'openline-isolated'
        or nets[0].find('model') is None
        or nets[0].find('model').get('type') != 'virtio'
    ):
        raise ValueError('network mismatch')
    balloons = devices.findall('memballoon')
    if len(balloons) != 1 or balloons[0].get('model') != 'none':
        raise ValueError('memballoon must be disabled')
    for ctrl in devices.findall('controller'):
        if ctrl.get('type') == 'virtio-serial':
            raise ValueError('virtio-serial controller forbidden')
        if ctrl.get('type') == 'usb' and ctrl.get('model') != 'none':
            raise ValueError('usb controller must be disabled')
    return {'configuration': 'MATCH', 'vm_execution': 'NOT_TESTED'}


NETWORK = '''<network>
  <name>openline-isolated</name>
  <bridge name="olvmt0" stp="off" delay="0"/>
  <dns enable="no"/>
  <ip address="192.168.251.1" netmask="255.255.255.0"/>
</network>
'''
FIREWALL = '''# Scoped additive tables; never flush the host ruleset. Load BEFORE guest creation.
table inet openline_vm {
 chain input {
  type filter hook input priority -310; policy accept;
  iifname "olvmt0" ct state established,related accept
  iifname "olvmt0" ip daddr 192.168.251.1 tcp dport 7443 accept
  iifname "olvmt0" counter drop
 }
 chain forward {
  type filter hook forward priority -310; policy accept;
  iifname "olvmt0" counter drop
  oifname "olvmt0" counter drop
 }
}
table bridge openline_vm_l2 {
 chain forward {
  type filter hook forward priority -310; policy accept;
  meta ibrname "olvmt0" counter drop
  meta obrname "olvmt0" counter drop
 }
}
'''


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--disk', required=True)
    p.add_argument('--seed', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=False)
    xml = domain(a.disk, a.seed)
    audit_domain(xml, a.disk, a.seed)
    for name, text in [('worker.xml', xml), ('network.xml', NETWORK), ('firewall.nft', FIREWALL)]:
        (out / name).write_text(text)
    print(json.dumps({'status': 'ASSETS_ONLY', 'vm_containment': 'NOT_TESTED', 'output': str(out)}))


if __name__ == '__main__':
    main()
