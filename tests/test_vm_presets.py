"""Static checks for the isolated lab VM presets: isolation defaults, no secrets, templates render."""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

VM = Path(__file__).resolve().parents[1] / 'presets' / 'isolated' / 'vm'
FAKE_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0 test@example'
SECRET_PATTERNS = [
    r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
    r'\bAKIA[0-9A-Z]{16}\b',
    r'\bsk-[A-Za-z0-9]{20,}\b',
    r'(?i)\b(password|passwd|token|api[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9+/_-]{12,}',
]


def read(*parts):
    return VM.joinpath(*parts).read_text(encoding='utf-8')


class VmPresetTests(unittest.TestCase):
    def test_no_secret_like_content(self):
        for path in VM.rglob('*'):
            if not path.is_file():
                continue
            text = path.read_text(encoding='utf-8', errors='replace')
            for pattern in SECRET_PATTERNS:
                self.assertIsNone(re.search(pattern, text), f'{path.name} matches {pattern}')

    def test_profiles_default_isolation(self):
        data = json.loads(read('common', 'profiles.json'))
        for key, value in data['isolation_defaults'].items():
            self.assertFalse(value, f'isolation default {key} must be false')
        self.assertFalse(data['profiles']['offline']['requires_egress_proxy'])
        self.assertTrue(data['profiles']['logged_egress']['requires_egress_proxy'])
        self.assertEqual(data['default_lab_subnet']['cidr'], '172.29.91.0/29')

    def test_user_data_is_key_only_and_secretless(self):
        text = read('common', 'user-data.template')
        self.assertIn('lock_passwd: true', text)
        self.assertIn('ssh_pwauth: false', text)
        self.assertIn('PasswordAuthentication no', text)
        self.assertIn('disable_root: true', text)
        self.assertNotIn('chpasswd', text)
        self.assertIsNone(re.search(r'(?<!lock_)passwd:', text))
        self.assertNotIn('plain_text_passwd', text)

    def test_offline_rules_have_no_outbound_exception(self):
        rules = read('common', 'nftables.offline.conf')
        output = rules.split('chain output', 1)[1]
        self.assertIn('policy drop', output)
        self.assertNotIn('daddr', output)
        self.assertNotIn('EGRESS', rules)

    def test_logged_egress_has_exactly_one_destination(self):
        rules = read('common', 'nftables.logged_egress.conf')
        output = rules.split('chain output', 1)[1]
        self.assertEqual(len(re.findall(r'\bdaddr\b', output)), 1)
        self.assertIn('__EGRESS_PROXY_IP__', output)

    def test_libvirt_network_is_isolated(self):
        root = ET.fromstring(read('libvirt', 'asg-lab-net.xml'))
        self.assertIsNone(root.find('forward'), 'isolated network must not have <forward>')
        self.assertEqual(root.find('ip').get('netmask'), '255.255.255.248')

    def test_hyperv_scripts_keep_isolation_and_leave_firewall_to_a_person(self):
        new_vm = read('hyperv', 'New-AsgLabVm.ps1')
        self.assertIn('SupportsShouldProcess', new_vm)
        self.assertIn('Disable-VMIntegrationService', new_vm)
        self.assertIn('-SwitchType Internal', new_vm)
        self.assertNotIn('External', new_vm.replace('external switch', ''))
        self.assertNotIn('NetFirewallRule', new_vm)
        self.assertNotIn('New-NetNat', new_vm)
        self.assertIn('AutomaticCheckpointsEnabled $false', new_vm)
        self.assertIn('PRIVATE KEY', new_vm)  # refuses private keys
        self.assertIn('New-NetFirewallRule', read('hyperv', 'Block-LabToHost.ps1'))
        freeze = read('hyperv', 'Invoke-AsgLabFreeze.ps1')
        self.assertLess(freeze.index('Disconnect-VMNetworkAdapter'), freeze.index('Save-VM -Name'))
        self.assertIn('cloud-images.ubuntu.com', read('hyperv', 'Convert-CloudImage.ps1'))
        self.assertIn('Get-FileHash', read('hyperv', 'Convert-CloudImage.ps1'))

    def test_other_platform_scripts_disable_sharing_and_use_no_nat(self):
        vbox = read('virtualbox', 'new-lab-vm.sh')
        for flag in ('--clipboard-mode disabled', '--draganddrop disabled', '--vrde off', '--nic1 hostonly'):
            self.assertIn(flag, vbox)
        self.assertNotIn('sharedfolder', vbox)
        self.assertNotIn('--nic1 nat', vbox)
        self.assertNotIn('bridged', vbox.replace('No NAT, no bridged adapter', ''))
        qemu = read('qemu', 'new-lab-vm.sh')
        self.assertIn('restrict=on', qemu)
        self.assertIn('hostfwd=tcp:127.0.0.1:', qemu)
        self.assertNotIn('-virtfs', qemu)
        libvirt = read('libvirt', 'new-lab-vm.sh')
        self.assertNotIn('--filesystem', libvirt.replace('No --filesystem', ''))
        self.assertIn('--graphics none', libvirt)

    def test_windows_template_has_only_a_placeholder_password(self):
        text = read('windows-guest', 'autounattend.template.xml')
        ET.fromstring(text.split('?>', 1)[1])
        self.assertIn('__LAB_ADMIN_PASSWORD__', text)

    @unittest.skipUnless(shutil.which('sh') and shutil.which('awk') and shutil.which('sed'), 'POSIX tools not available')
    def test_render_seed_fills_every_placeholder(self):
        script = VM / 'common' / 'render-seed.sh'
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / 'lab.pub'
            key.write_text(FAKE_KEY + '\n', encoding='utf-8')
            for profile, extra in (('offline', []), ('logged_egress', ['--egress-ip', '172.29.91.1', '--egress-port', '3128'])):
                out = Path(tmp) / profile
                result = subprocess.run(['sh', str(script), '--name', 'lab-test', '--pubkey', str(key), '--out', str(out),
                                         '--profile', profile] + extra, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                user_data = (out / 'user-data').read_text(encoding='utf-8')
                self.assertIsNone(re.search(r'__[A-Z_]+__', user_data))
                self.assertIn(FAKE_KEY, user_data)
                self.assertIn('table inet asg_lab', user_data)
                self.assertIn('profile', user_data)
                self.assertTrue(user_data.startswith('#cloud-config'))
                self.assertIn('172.29.91.2/29', (out / 'network-config').read_text(encoding='utf-8'))
                self.assertIn('instance-id: lab-test-', (out / 'meta-data').read_text(encoding='utf-8'))

    @unittest.skipUnless(shutil.which('sh'), 'sh not available')
    def test_render_seed_rejects_private_keys_and_bad_names(self):
        script = VM / 'common' / 'render-seed.sh'
        with tempfile.TemporaryDirectory() as tmp:
            priv = Path(tmp) / 'priv'
            priv.write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nxxx\n', encoding='utf-8')
            pub = Path(tmp) / 'lab.pub'
            pub.write_text(FAKE_KEY + '\n', encoding='utf-8')
            for name, keyfile in (('lab-test', priv), ('../evil', pub)):
                result = subprocess.run(['sh', str(script), '--name', name, '--pubkey', str(keyfile),
                                         '--out', str(Path(tmp) / 'o')], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
            result = subprocess.run(['sh', str(script), '--name', 'lab-test', '--pubkey', str(pub), '--out', str(Path(tmp) / 'o'),
                                     '--profile', 'logged_egress'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, 'logged_egress without a proxy must fail closed')


    def test_ssh_helper_is_noninteractive_and_bounded(self):
        text = read('hyperv', 'Invoke-AsgLabSsh.ps1')
        for needle in ('BatchMode=yes', 'ForwardAgent=no', '-RedirectStandardOutput', 'WaitForExit', 'base64'):
            self.assertIn(needle, text)

    def test_inventory_example_has_names_only_and_example_addresses(self):
        root = Path(__file__).resolve().parents[1]
        data = json.loads((root / 'setup' / 'inventory.example.json').read_text(encoding='utf-8'))
        self.assertEqual({h['role'] for h in data['hosts'].values()}, {'parent', 'hub', 'isolated'})
        self.assertEqual(data['hosts']['hub']['asg_bind'], '127.0.0.1')
        for host in data['hosts'].values():
            self.assertTrue(host['address'].startswith('192.0.2.'))  # RFC 5737 documentation range
        self.assertEqual(data['secrets']['policy'].split('.')[0], 'Values never appear in this file')
        self.assertIn('inventory.local.json', (root / '.gitignore').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
