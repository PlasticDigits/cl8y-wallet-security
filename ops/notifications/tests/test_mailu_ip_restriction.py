import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('restriction', Path(__file__).parents[1] / 'restrict-mailu-ip.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Restriction(unittest.TestCase):
    def setUp(self):
        self.custody = dict(state='disabled-staged', smtp_token='synthetic-sender-token', token_id='77',
                            sender=m.e.SENDER, host='mail.cl8y.com', port=587, authorized_ips=m.e.STAGED_IPS)
        self.version = 1
        self.ips = m.e.STAGED_IPS
        self.enabled = False
        self.calls = []
        self.cas_fail = False

    def request(self, base, token, path, method='GET', data=None):
        self.calls.append((path, method, data))
        if path.endswith('/envs'):
            self.assertEqual(method, 'GET')
            return [{'key': 'API_TOKEN', 'value': 'synthetic-control'}]
        self.assertEqual(base, 'https://mail.cl8y.com/api/v1')
        self.assertEqual(token, 'synthetic-control')
        if path == '/user/' + m.e.SENDER:
            self.assertEqual(method, 'GET')
            return dict(comment=m.e.COMMENT, enabled=self.enabled, global_admin=False,
                        enable_imap=False, enable_pop=False, allow_spoofing=False,
                        forward_enabled=False, reply_enabled=False)
        self.assertEqual(path, '/token/77')
        if method == 'PATCH':
            self.assertEqual(set(data), {'AuthorizedIP'})
            self.ips = data['AuthorizedIP']
            return {}
        self.assertEqual(method, 'GET')
        return dict(email=m.e.SENDER, comment=m.e.COMMENT, AuthorizedIP=self.ips)

    def read(self):
        return self.custody.copy(), self.version

    def write(self, data, version):
        self.assertEqual(version, self.version)
        if self.cas_fail: raise RuntimeError('synthetic_conflict')
        self.custody = data.copy()
        self.version += 1

    def run_action(self):
        with patch.dict(m.os.environ, COOLIFY_URL='http://synthetic.invalid', COOLIFY_WIRE_TOKEN='synthetic'), \
             patch.object(m, 'read_custody', side_effect=self.read), \
             patch.object(m, 'write_custody', side_effect=self.write), \
             patch.object(m.e, 'request', side_effect=self.request):
            return m.restrict()

    def test_exact_token_ip_cas_and_idempotent_no_sender_enable(self):
        result = self.run_action()
        self.assertTrue(result['changed'])
        self.assertEqual(self.custody['state'], m.STATE)
        self.assertEqual(self.custody['smtp_token'], 'synthetic-sender-token')
        self.assertEqual(self.ips, ['168.119.120.255/32'])
        self.assertFalse(self.enabled)
        mutations = [call for call in self.calls if call[1] != 'GET']
        self.assertEqual(mutations, [('/token/77', 'PATCH', {'AuthorizedIP': m.VERIFIED_IPS})])
        self.assertNotIn('synthetic', json.dumps(result))
        self.assertFalse(self.run_action()['changed'])
        self.assertEqual(len([call for call in self.calls if call[1] != 'GET']), 1)

    def test_enabled_sender_or_unexpected_existing_ip_never_mutates(self):
        for changed in ('enabled', 'ip'):
            self.setUp()
            if changed == 'enabled': self.enabled = True
            else: self.ips = ['0.0.0.0/0']
            with self.assertRaises(RuntimeError): self.run_action()
            self.assertFalse(any(call[1] != 'GET' for call in self.calls))

    def test_cas_failure_restores_only_owned_token_to_test_net(self):
        self.cas_fail = True
        with self.assertRaises(RuntimeError): self.run_action()
        self.assertEqual(self.ips, m.e.STAGED_IPS)
        self.assertEqual(self.custody['state'], 'disabled-staged')
        self.assertFalse(self.enabled)

    def test_readback_mismatch_compensates_own_custody_successor(self):
        original = self.read
        count = 0
        def readback():
            nonlocal count
            count += 1
            data, version = original()
            return (dict(data, host='synthetic-conflict'), version) if count == 2 else (data, version)
        with patch.object(self, 'read', side_effect=readback):
            with self.assertRaises(RuntimeError): self.run_action()
        self.assertEqual(self.ips, m.e.STAGED_IPS)
        self.assertEqual(self.custody['state'], 'disabled-staged')


if __name__ == '__main__':
    unittest.main()
