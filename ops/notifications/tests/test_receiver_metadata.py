import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('receiver', Path(__file__).parents[1] / 'receiver-metadata.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ReceiverMetadata(unittest.TestCase):
    def test_remote_and_local_roles_are_preserved_without_unrelated_data(self):
        logs = '\n'.join((
            '2026-10-31T07:07:06Z unrelated person@example.invalid 203.0.113.99',
            '2026-10-31T07:07:08.139508Z submission-login: Info: Login aborted: Connection closed '
            '(no auth attempts in 0 secs): user=<private@example.invalid>, rip=168.119.120.255, '
            'lip=172.19.0.8, lport=587, TLS, session=<private-session>',
            '2026-10-31T07:07:09Z no owned peer'))
        result = m.summarize(logs)
        self.assertTrue(result['window_covered'])
        self.assertFalse(result['source_ip_cleared'])
        row, = result['owned_window_rows']
        self.assertEqual(row['address_roles'], [{'role': 'owned_gateway_host', 'field': 'rip'},
                                               {'role': 'redacted', 'field': 'lip'}])
        self.assertEqual(row['port_fields'], [{'field': 'lport', 'is_587': True}])
        self.assertTrue(row['no_auth_attempts'])
        for private in ('example.invalid', '172.19.0.8', '203.0.113.99', 'private-session'):
            self.assertNotIn(private, json.dumps(result))

    def test_local_or_unclassified_owned_address_never_becomes_remote_proof(self):
        for peer in ('rip=203.0.113.1, lip=168.119.120.255', 'upstream=168.119.120.255',
                     '168.119.120.255'):
            result = m.summarize('2026-10-31T07:07:08Z smtp-login: ' + peer + ' TLS lport=587')
            self.assertFalse(result['source_ip_cleared'])
            self.assertNotIn({'role': 'owned_gateway_host', 'field': 'rip'},
                             result['owned_window_rows'][0]['address_roles'])

    def test_exact_address_and_window_matching(self):
        for line in ('2026-10-31T07:07:08Z rip=168.119.120.2551',
                     '2026-10-31T07:07:20Z rip=168.119.120.255',
                     '2026-10-31T07:07:08Z rip=203.0.113.1'):
            self.assertEqual(m.summarize(line)['owned_window_rows'], [])

    def test_invalid_or_oversized_logs_fail_closed(self):
        for logs in (None, {}, 'x' * 2_000_001):
            with self.assertRaisesRegex(RuntimeError, 'logs_bound'):
                m.summarize(logs)


if __name__ == '__main__':
    unittest.main()
