import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('enablement', Path(__file__).parents[1] / 'enable-owned-smoke.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Enablement(unittest.TestCase):
    def setUp(self):
        self.values = {}
        self.users = {}
        self.calls = []
        self.fail_receiver_cas = False
        self.fail_sender_disable = False
        for index, scope in enumerate(m.SCOPES):
            self.values[scope['path']] = (dict(state=scope['initial'], token_id=str(index + 77),
                host='mail.cl8y.com', port=scope['port'], authorized_ips=scope['ips'],
                **{scope['address_key']: scope['address'], scope['token_key']: 'synthetic-account-token'}), 1)
            self.users[scope['address']] = dict(comment=scope['comment'], quota_bytes=10485760,
                enabled=False, enable_imap=scope['imap'], global_admin=False, enable_pop=False,
                allow_spoofing=False, forward_enabled=False, reply_enabled=False)

    def request(self, base, token, path, method='GET', data=None):
        self.calls.append((path, method, data))
        if path.endswith('/envs'): return [{'key': 'API_TOKEN', 'value': 'synthetic-control'}]
        self.assertEqual(token, 'synthetic-control')
        if path.startswith('/user/'):
            user = self.users[path[6:]]
            if method == 'PATCH':
                self.assertEqual(set(data), {'enabled'})
                if self.fail_sender_disable and path == '/user/' + m.SCOPES[0]['address'] and data['enabled'] is False:
                    raise RuntimeError('synthetic-provider-unavailable')
                user.update(data)
            else: self.assertEqual(method, 'GET')
            return user
        self.assertEqual(method, 'GET')
        scope = m.SCOPES[int(path.rsplit('/', 1)[1]) - 77]
        return dict(email=scope['address'], comment=scope['comment'], AuthorizedIP=scope['ips'])

    def write(self, path, data, version):
        if self.fail_receiver_cas and path == m.SCOPES[1]['path'] and data['state'] == m.TARGET:
            raise RuntimeError('synthetic-cas-conflict')
        self.assertEqual(self.values[path][1], version)
        self.values[path] = (data.copy(), version + 1)

    def action(self):
        with patch.dict(m.os.environ, COOLIFY_URL='http://synthetic.invalid', COOLIFY_WIRE_TOKEN='synthetic'), \
             patch.object(m, 'read', side_effect=lambda path: self.values[path]), \
             patch.object(m, 'write', side_effect=self.write), \
             patch.object(m.e, 'request', side_effect=self.request):
            return m.enable()

    def test_only_two_fixed_accounts_enabled_with_unchanged_credentials(self):
        result = self.action()
        self.assertEqual(result['accounts_changed'], 2)
        self.assertEqual([call for call in self.calls if call[1] != 'GET'],
                         [('/user/' + scope['address'], 'PATCH', {'enabled': True}) for scope in m.SCOPES])
        self.assertNotIn('synthetic', json.dumps(result))
        self.assertEqual(self.action()['accounts_changed'], 0)

    def test_foreign_or_broadened_custody_never_enables_accounts(self):
        for field, value in (('authorized_ips', ['0.0.0.0/0']), ('token_id', '../foreign')):
            self.setUp()
            self.values[m.SCOPES[1]['path']][0][field] = value
            with self.assertRaises(RuntimeError): self.action()
            self.assertFalse(any(call[1] != 'GET' for call in self.calls))

    def test_partial_cas_failure_disables_both_and_restores_only_own_custody(self):
        self.fail_receiver_cas = True
        with self.assertRaises(RuntimeError): self.action()
        for scope in m.SCOPES:
            self.assertFalse(self.users[scope['address']]['enabled'])
            self.assertEqual(self.values[scope['path']][0]['state'], scope['initial'])

    def test_compensation_attempts_second_account_even_if_first_disable_fails(self):
        self.fail_receiver_cas = self.fail_sender_disable = True
        with self.assertRaisesRegex(RuntimeError, 'requires_reconciliation'): self.action()
        self.assertFalse(self.users[m.SCOPES[1]['address']]['enabled'])
        self.assertIn(('/user/' + m.SCOPES[1]['address'], 'PATCH', {'enabled': False}), self.calls)


if __name__ == '__main__':
    unittest.main()
