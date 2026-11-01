import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import urllib.error
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('retirement', Path(__file__).parents[1] / 'retire-smoke-mailbox.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Retirement(unittest.TestCase):
    def setUp(self):
        self.data = dict(state='enabled-owned-smoke', recipient=m.s.RECIPIENT, imap_token='synthetic-owned-token',
                         token_id='78', host='mail.cl8y.com', port=993, authorized_ips=m.s.IPS)
        self.version = 2
        self.enabled = self.token_present = True
        self.foreign_token = self.cas_fail = False
        self.calls = []

    def request(self, base, token, path, method='GET', data=None):
        self.calls.append((path, method, data))
        if path.endswith('/envs'): return [{'key': 'API_TOKEN', 'value': 'synthetic-control'}]
        self.assertEqual(base, 'https://mail.cl8y.com/api/v1')
        self.assertEqual(token, 'synthetic-control')
        if path == '/user/' + m.s.RECIPIENT:
            if method == 'PATCH':
                self.assertEqual(data, {'enabled': False}); self.enabled = False
            else: self.assertEqual(method, 'GET')
            return dict(comment=m.s.COMMENT, quota_bytes=10485760, enabled=self.enabled,
                        enable_imap=True, global_admin=False, enable_pop=False, allow_spoofing=False,
                        forward_enabled=False, reply_enabled=False)
        self.assertEqual(path, '/token/78')
        if method == 'DELETE': self.token_present = False; return {}
        self.assertEqual(method, 'GET')
        if not self.token_present: raise urllib.error.HTTPError('synthetic', 404, '', {}, None)
        return dict(email='foreign@example.invalid' if self.foreign_token else m.s.RECIPIENT,
                    comment=m.s.COMMENT, AuthorizedIP=m.s.IPS)

    def store(self, argv, **kwargs):
        self.assertEqual(argv, ['bao-admin', 'write', '-format=json', m.s.PATH, '-'])
        body = json.loads(kwargs['input'])
        self.assertEqual(body['options'], {'cas': self.version})
        self.assertNotIn('imap_token', body['data'])
        if not self.cas_fail: self.data = body['data']; self.version += 1
        return subprocess.CompletedProcess(argv, 1 if self.cas_fail else 0, b'', b'')

    def action(self):
        with patch.dict(m.os.environ, COOLIFY_URL='http://synthetic.invalid', COOLIFY_WIRE_TOKEN='synthetic'), \
             patch.object(m, 'read', side_effect=lambda: (self.data.copy(), self.version)), \
             patch.object(m.e, 'request', side_effect=self.request), \
             patch.object(m.subprocess, 'run', side_effect=self.store):
            return m.retire()

    def test_only_owned_receiver_disabled_and_token_revoked_then_read_only_repeat(self):
        result = self.action()
        self.assertTrue(result['changed'])
        self.assertEqual([call for call in self.calls if call[1] != 'GET'],
                         [('/user/' + m.s.RECIPIENT, 'PATCH', {'enabled': False}), ('/token/78', 'DELETE', None)])
        self.assertNotIn('synthetic', json.dumps(result))
        count = len(self.calls)
        self.assertFalse(self.action()['changed'])
        self.assertTrue(all(call[1] == 'GET' for call in self.calls[count:]))

    def test_foreign_token_is_never_revoked_and_no_account_disabled(self):
        self.foreign_token = True
        with self.assertRaisesRegex(RuntimeError, 'scope_conflict'): self.action()
        self.assertTrue(self.enabled)
        self.assertTrue(self.token_present)
        self.assertFalse(any(call[1] != 'GET' for call in self.calls))

    def test_partial_cleanup_is_recoverable_without_reissuing_credentials(self):
        self.enabled = self.token_present = False
        self.assertTrue(self.action()['changed'])
        self.assertFalse(any(call[1] != 'GET' for call in self.calls))

    def test_cas_failure_stays_disabled_revoked_and_preserves_old_custody(self):
        self.cas_fail = True
        with self.assertRaisesRegex(RuntimeError, 'cas_failed'): self.action()
        self.assertFalse(self.enabled)
        self.assertFalse(self.token_present)
        self.assertEqual(self.data['state'], 'enabled-owned-smoke')


if __name__ == '__main__':
    unittest.main()
