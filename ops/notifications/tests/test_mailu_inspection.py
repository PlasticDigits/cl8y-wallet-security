import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('inspection', Path(__file__).parents[1] / 'inspect-mailu.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Inspection(unittest.TestCase):
    def setUp(self):
        self.custody = dict(state='disabled-staged', smtp_token='synthetic-sender-token', token_id='77',
                            sender=m.enrollment.SENDER, host='mail.cl8y.com', port=587,
                            authorized_ips=m.enrollment.STAGED_IPS)
        self.user = dict(comment=m.enrollment.COMMENT, enabled=False, global_admin=False,
                         enable_imap=False, enable_pop=False, allow_spoofing=False,
                         forward_enabled=False, reply_enabled=False)
        self.token = dict(email=m.enrollment.SENDER, comment=m.enrollment.COMMENT,
                          AuthorizedIP=m.enrollment.STAGED_IPS)

    def request(self, base, token, path, method='GET', data=None):
        self.assertEqual(method, 'GET')
        self.assertIsNone(data)
        if path == '/services/' + m.enrollment.SERVICE + '/envs':
            return [{'key': 'API_TOKEN', 'value': 'synthetic-control-token'}]
        self.assertEqual(base, 'https://mail.cl8y.com/api/v1')
        self.assertEqual(token, 'synthetic-control-token')
        return {'/user/' + m.enrollment.SENDER: self.user, '/token/77': self.token}[path]

    def test_read_only_exact_disabled_custody(self):
        with patch.dict(m.os.environ, COOLIFY_URL='http://synthetic.invalid', COOLIFY_WIRE_TOKEN='synthetic'), \
             patch.object(m.enrollment, 'vault_read', return_value=self.custody), \
             patch.object(m.enrollment, 'request', side_effect=self.request) as request:
            result = m.inspect()
        self.assertTrue(result['read_only'])
        self.assertEqual(request.call_count, 3)
        self.assertNotIn('synthetic', json.dumps(result))
        self.assertNotIn(m.enrollment.SENDER, json.dumps(result))

    def test_missing_or_wrong_custody_never_enrolls(self):
        for custody in (None, {}, dict(self.custody, token_id='../other'),
                        dict(self.custody, authorized_ips=['0.0.0.0/0'])):
            with patch.object(m.enrollment, 'vault_read', return_value=custody), \
                 patch.object(m.enrollment, 'request') as request:
                with self.assertRaises(RuntimeError):
                    m.inspect()
                request.assert_not_called()

    def test_enabled_or_unrestricted_mailu_scope_is_refused(self):
        for changed in ('sender', 'token'):
            self.setUp()
            if changed == 'sender': self.user['enabled'] = True
            else: self.token['AuthorizedIP'] = ['0.0.0.0/0']
            with patch.dict(m.os.environ, COOLIFY_URL='http://synthetic.invalid', COOLIFY_WIRE_TOKEN='synthetic'), \
                 patch.object(m.enrollment, 'vault_read', return_value=self.custody), \
                 patch.object(m.enrollment, 'request', side_effect=self.request):
                with self.assertRaises(RuntimeError):
                    m.inspect()


if __name__ == '__main__':
    unittest.main()
