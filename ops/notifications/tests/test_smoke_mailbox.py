import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import urllib.error
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('smoke', Path(__file__).parents[1] / 'enroll-smoke-mailbox.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SmokeMailbox(unittest.TestCase):
    def setUp(self):
        self.custody = None
        self.user = None
        self.calls = []
        self.store_fail = False

    def request(self, base, token, path, method='GET', data=None):
        self.calls.append((path, method, data))
        if path.endswith('/envs'): return [{'key': 'API_TOKEN', 'value': 'synthetic-control'}]
        self.assertEqual(base, 'https://mail.cl8y.com/api/v1')
        self.assertEqual(token, 'synthetic-control')
        if path == '/user/' + m.RECIPIENT:
            if self.user is None: raise urllib.error.HTTPError('synthetic', 404, '', {}, None)
            return self.user
        if path == '/user' and method == 'POST':
            self.user = data.copy()
            self.assertFalse(data['enabled'])
            self.assertTrue(data['enable_imap'])
            return {}
        if path == '/token' and method == 'POST':
            self.assertEqual(data['email'], m.RECIPIENT)
            self.assertEqual(data['AuthorizedIP'], m.IPS)
            return {'id': '78', 'token': 'synthetic-owned-imap-token'}
        if path == '/token/78':
            return dict(email=m.RECIPIENT, comment=m.COMMENT, AuthorizedIP=m.IPS)
        self.fail('unexpected operation')

    def store(self, argv, **kwargs):
        self.assertEqual(argv, ['bao-admin', 'write', '-format=json', m.PATH, '-'])
        payload = json.loads(kwargs['input'])
        self.assertEqual(payload['options'], {'cas': 0})
        self.assertNotIn('synthetic-control', kwargs['input'].decode())
        self.assertNotIn('raw_password', kwargs['input'].decode())
        if not self.store_fail: self.custody = payload['data']
        return subprocess.CompletedProcess(argv, 1 if self.store_fail else 0, b'', b'')

    def action(self):
        with patch.dict(m.os.environ, COOLIFY_URL='http://synthetic.invalid', COOLIFY_WIRE_TOKEN='synthetic'), \
             patch.object(m, 'read_custody', side_effect=lambda: self.custody), \
             patch.object(m.e, 'request', side_effect=self.request), \
             patch.object(m.subprocess, 'run', side_effect=self.store):
            return m.prepare()

    def test_disabled_owned_preparation_and_read_only_repeat(self):
        result = self.action()
        self.assertTrue(result['created'])
        self.assertNotIn('synthetic', json.dumps(result))
        mutations = sum(call[1] != 'GET' for call in self.calls)
        self.assertFalse(self.action()['created'])
        self.assertEqual(sum(call[1] != 'GET' for call in self.calls), mutations)
        self.assertFalse(self.user['enabled'])

    def test_preexisting_account_is_not_adopted_or_rotated(self):
        self.user = {'enabled': False}
        with self.assertRaisesRegex(RuntimeError, 'preexisting_smoke_mailbox_not_adopted'):
            self.action()
        self.assertFalse(any(call[1] != 'GET' for call in self.calls))

    def test_store_failure_revokes_only_new_token_and_keeps_account_disabled(self):
        self.store_fail = True
        with self.assertRaises(RuntimeError): self.action()
        self.assertIn(('/token/78', 'DELETE', None), self.calls)
        self.assertFalse(self.user['enabled'])
        self.assertIsNone(self.custody)


if __name__ == '__main__':
    unittest.main()
