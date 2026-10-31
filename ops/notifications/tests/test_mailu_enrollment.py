import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
import urllib.error
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('enrollment', Path(__file__).parents[1] / 'enroll-mailu.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Enrollment(unittest.TestCase):
    def test_scoped_disabled_custody_and_idempotent_readback(self):
        store = None
        user = None
        calls = []
        def request(base, token, path, method='GET', data=None):
            nonlocal user
            calls.append((base, path, method, data))
            if path.endswith('/envs'):
                return [{'key': 'API_TOKEN', 'value': 'synthetic-admin-only'}]
            self.assertEqual(base, 'https://mail.cl8y.com/api/v1')
            self.assertEqual(token, 'synthetic-admin-only')
            if path == '/user/' + m.SENDER:
                if user is None:
                    raise urllib.error.HTTPError('synthetic', 404, '', {}, None)
                return user
            if path == '/user' and method == 'POST':
                user = data.copy()
                return {'code': 200}
            if path == '/token' and method == 'POST':
                self.assertEqual(data['AuthorizedIP'], ['192.0.2.1/32'])
                return {'id': '77', 'token': 'synthetic-sender-only'}
            if path == '/token/77':
                return {'email': m.SENDER, 'comment': m.COMMENT, 'AuthorizedIP': m.STAGED_IPS}
            self.fail('unexpected API operation')
        def run(argv, **kwargs):
            nonlocal store
            self.assertEqual(argv, ['bao-admin', 'write', '-format=json', m.PATH, '-'])
            body = json.loads(kwargs['input'])
            self.assertEqual(body['options'], {'cas': 0})
            self.assertNotIn('synthetic-admin-only', kwargs['input'].decode())
            store = body['data']
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        output = io.StringIO()
        with patch.dict(m.os.environ, COOLIFY_URL='http://10.10.0.2:8000', COOLIFY_WIRE_TOKEN='synthetic-wire'), patch.object(m, 'vault_read', side_effect=lambda: store), patch.object(m, 'request', side_effect=request), patch.object(m.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(output):
            m.prepare()
            mutation_count = sum(c[2] != 'GET' for c in calls)
            m.prepare()
            self.assertEqual(sum(c[2] != 'GET' for c in calls), mutation_count)
        self.assertEqual(store['smtp_token'], 'synthetic-sender-only')
        self.assertNotIn('synthetic', output.getvalue())
        self.assertNotIn(m.SENDER, output.getvalue())
        self.assertFalse(user['enabled'])
        self.assertFalse(user['global_admin'])
        self.assertFalse(user['allow_spoofing'])

    def test_preexisting_mailbox_is_never_adopted_or_rotated(self):
        with patch.dict(m.os.environ, COOLIFY_URL='http://10.10.0.2:8000', COOLIFY_WIRE_TOKEN='synthetic'), patch.object(m, 'vault_read', return_value=None), patch.object(m, 'request', side_effect=[[{'key':'API_TOKEN','value':'synthetic'}], {'enabled':True}]) as request:
            with self.assertRaisesRegex(RuntimeError, 'sender_exists_without_owned_custody'):
                m.prepare()
            self.assertEqual(request.call_count, 2)

if __name__ == '__main__':
    unittest.main()
