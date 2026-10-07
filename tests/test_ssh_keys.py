#!/usr/bin/env python3
"""Regression tests using real OpenSSH keys and isolated script sections.

No system users, SSH configuration, or package state are modified.
Run: python3 -m unittest discover -s tests -v
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SSHKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.keys = {}
        for kind in ('ed25519', 'rsa', 'ecdsa', 'ecdsa384', 'ecdsa521'):
            path = Path(cls.workspace.name) / kind
            algorithm = 'ecdsa' if kind.startswith('ecdsa') else kind
            bits = ['-b', kind[5:]] if kind != algorithm else []
            subprocess.run(['ssh-keygen', '-q', '-t', algorithm, *bits, '-N', '',
                            '-C', 'original comment', '-f', str(path)], check=True)
            cls.keys[kind] = path.with_suffix('.pub').read_text().strip()

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.auth = self.home / '.ssh' / 'authorized_keys'
        self.auth.parent.mkdir(mode=0o700)

    def write_keys(self, text):
        self.auth.write_text(text)
        self.auth.chmod(0o600)

    def run_shell(self, body, key='', extra=''):
        env = dict(os.environ, TEST_HOME=str(self.home), TEST_KEY=key,
                   TMPDIR=str(self.home))
        prelude = '''
set -euo pipefail
source "$1/lib/ssh-keys.sh"
log() { :; }
info() { :; }
warn() { printf '%s\\n' "$*"; }
getent() {
  if [[ "$1" == group ]]; then printf 'sudo:x:27:deploy\\n';
  else printf 'deploy:x:1000:1000::%s:/bin/bash\\n' "$TEST_HOME"; fi
}
id() { return 0; }
groups() { echo 'deploy : deploy sudo'; }
chown() { :; }
adduser() { echo unexpected-adduser; exit 99; }
usermod() { echo unexpected-usermod; exit 99; }
'''
        return subprocess.run(['bash', '-c', prelude + extra + body,
                               'test', str(ROOT)], env=env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def init(self, key, extra=''):
        text = (ROOT / 'init-user.sh').read_text()
        body = text[text.index('USERNAME='):text.index('# ─── Done')]
        return self.run_shell('set -- deploy "$TEST_KEY"\n' + body, key, extra)

    def hardening(self, extra=''):
        text = (ROOT / 'vps-hardening.sh').read_text()
        body = text[text.index('# ─── 0.'):text.index('# ─── 1.')]
        return self.run_shell(body, extra=extra)

    def verify(self, extra=''):
        text = (ROOT / 'verify.sh').read_text()
        body = text[text.index('section "User & SSH Key"'):
                    text.index('section "SSH Hardening"')]
        # verify.sh intentionally does not use errexit.
        helpers = '''
set +e
FAIL_COUNT=0
pass() { printf 'PASS %s\\n' "$*"; }
fail() { ((FAIL_COUNT++)); printf 'FAIL %s\\n' "$*"; }
section() { :; }
'''
        return self.run_shell(helpers + body + '\nexit "$FAIL_COUNT"\n', extra=extra)

    def test_algorithms_and_repeated_initialization(self):
        for kind, key in self.keys.items():
            with self.subTest(kind=kind):
                self.auth.unlink(missing_ok=True)
                self.assertEqual(self.init(key).returncode, 0)
                before = self.auth.read_bytes()
                self.assertEqual(self.init(key).returncode, 0)
                self.assertEqual(self.init(key.rsplit('original comment', 1)[0]
                                           + 'different comment').returncode, 0)
                self.assertEqual(self.auth.read_bytes(), before)
                self.assertEqual(self.hardening().returncode, 0)
                self.assertEqual(self.verify().returncode, 0)

    def test_invalid_input_never_changes_authorized_keys(self):
        bad_keys = ['ssh-ed25519 not-a-key', 'ssh-rsa not-a-key',
                    'ecdsa-sha2-nistp256 not-a-key', 'ssh-ecdsa not-a-key',
                    'ssh-ed25519AAAA not-a-key', '', '# comment',
                    self.keys['ed25519'] + '\nssh-rsa not-a-key',
                    self.keys['ed25519'] + '\r',
                    self.keys['ed25519'].replace('ssh-ed25519', 'ssh-rsa', 1)]
        for existing in (False, True):
            for key in bad_keys:
                with self.subTest(existing=existing, key=key):
                    if existing:
                        self.write_keys('ssh-ed25519 not-a-key\n')
                        before = self.auth.read_bytes()
                        mode = self.auth.stat().st_mode
                    else:
                        self.auth.unlink(missing_ok=True)
                    self.assertNotEqual(self.init(key).returncode, 0)
                    if existing:
                        self.assertEqual(self.auth.read_bytes(), before)
                        self.assertEqual(self.auth.stat().st_mode, mode)
                    else:
                        self.assertFalse(self.auth.exists())

    def test_malformed_existing_lines_and_unterminated_last_line(self):
        self.write_keys('# comment\nssh-ed25519 not-a-key')
        self.assertNotEqual(self.hardening().returncode, 0)
        self.assertNotEqual(self.verify().returncode, 0)
        self.assertEqual(self.init(self.keys['ecdsa']).returncode, 0)
        self.assertEqual(self.auth.read_text(), '# comment\nssh-ed25519 not-a-key\n'
                         + self.keys['ecdsa'] + '\n')
        before = self.auth.read_bytes()
        self.assertEqual(self.init(self.keys['ecdsa']).returncode, 0)
        self.assertEqual(self.auth.read_bytes(), before)
        self.assertEqual(self.hardening().returncode, 0)
        self.assertEqual(self.verify().returncode, 0)
        self.write_keys(self.keys['rsa'])  # valid final line without newline
        self.assertEqual(self.hardening().returncode, 0)
        self.assertEqual(self.verify().returncode, 0)

    def test_existing_duplicates_options_and_invalid_trailing_line(self):
        key = self.keys['ed25519']
        self.write_keys('command="echo hello world",no-port-forwarding ' + key
                        + '\n' + key + '\nssh-rsa not-a-key\n')
        before = self.auth.read_bytes()
        self.assertEqual(self.init(key).returncode, 0)
        self.assertEqual(self.auth.read_bytes(), before)
        self.assertEqual(self.hardening().returncode, 0)
        self.assertEqual(self.verify().returncode, 0)

    def test_empty_missing_and_comment_only_files(self):
        for content in (None, '', '# comment\n\n'):
            with self.subTest(content=content):
                self.auth.unlink(missing_ok=True)
                if content is not None:
                    self.write_keys(content)
                self.assertNotEqual(self.hardening().returncode, 0)
                self.assertNotEqual(self.verify().returncode, 0)

    def test_missing_parser_and_temporary_file_cleanup(self):
        self.write_keys(self.keys['ed25519'] + '\n')
        before = self.auth.read_bytes()
        extra = 'command() { if [[ "$1" == -v && "$2" == ssh-keygen ]]; then return 1; else builtin command "$@"; fi; }\n'
        self.assertNotEqual(self.init(self.keys['rsa'], extra).returncode, 0)
        self.assertEqual(self.auth.read_bytes(), before)
        self.assertNotEqual(self.hardening(extra).returncode, 0)
        self.assertNotEqual(self.verify(extra).returncode, 0)
        self.assertEqual(self.init(self.keys['rsa']).returncode, 0)
        self.assertNotEqual(self.init('ssh-ed25519 not-a-key').returncode, 0)
        self.assertEqual(list(self.home.glob('tmp.*')), [])

    def test_parser_failure_is_closed(self):
        self.write_keys(self.keys['ed25519'] + '\n')
        before = self.auth.read_bytes()
        extra = 'ssh-keygen() { return 127; }\n'
        self.assertNotEqual(self.init(self.keys['rsa'], extra).returncode, 0)
        self.assertEqual(self.auth.read_bytes(), before)
        self.assertNotEqual(self.hardening(extra).returncode, 0)
        self.assertNotEqual(self.verify(extra).returncode, 0)


if __name__ == '__main__':
    unittest.main()
