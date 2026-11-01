import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('sessions', Path(__file__).parents[1] / 'owned-trial-session-count.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SessionCount(unittest.TestCase):
    def test_identity_stays_in_parameter_channel_and_only_counts_return(self):
        data = dict(state='owned-unfunded-smoke', source_sha=m.SOURCE, owner_key='0' * 63 + '1',
                    candidate_key='0' * 63 + '2', initial_uids=[])
        response = subprocess.CompletedProcess([], 0, json.dumps({'data': {'data': data}}).encode(), b'')
        def query(sql, params):
            self.assertNotIn(params[0], sql)
            self.assertEqual(params[0], params[1])
            self.assertTrue(params[0].startswith('terra1'))
            self.assertNotRegex(sql.lower(), r'\b(?:insert|update|delete|alter)\b')
            return [(1, 0)]
        with patch.object(m.subprocess, 'run', return_value=response) as run:
            self.assertEqual(m.active_sessions(query), {'profile_present': True, 'active_session_count': 0})
            self.assertEqual(run.call_args.args[0], ['bao-admin', 'read', '-format=json', m.PATH])

    def test_missing_or_foreign_custody_never_queries_or_creates(self):
        for response in (subprocess.CompletedProcess([], 2, b'', b'No value found at synthetic'),
                         subprocess.CompletedProcess([], 0, b'{"data":{"data":{}}}', b'')):
            with patch.object(m.subprocess, 'run', return_value=response) as run, patch.object(m, 'live') as live:
                with self.assertRaises(RuntimeError): m.owned_anchor()
                self.assertEqual(run.call_count, 1)
                live.address.assert_not_called()


if __name__ == '__main__':
    unittest.main()
