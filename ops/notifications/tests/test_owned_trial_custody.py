import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('owned_delivery_custody', Path(__file__).parents[1] / 'owned-delivery-smoke.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class TrialCustody(unittest.TestCase):
    def test_same_private_profile_recovers_without_key_argv_or_local_secret_files(self):
        saved = None
        writes = 0
        def run(argv, **kwargs):
            nonlocal saved, writes
            self.assertEqual(argv[0], 'bao-admin')
            self.assertEqual(argv[3], 'secret/data/groups/cl8y-wallet-security/mailu_smoke_trial')
            if argv[1] == 'write':
                self.assertEqual(argv[-1], '-')
                body = json.loads(kwargs['input'])
                self.assertEqual(body['options'], {'cas': 0})
                self.assertEqual(set(body['data']), {'state', 'source_sha', 'owner_key', 'candidate_key', 'initial_uids'})
                saved = body['data']; writes += 1
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            if saved is None:
                return subprocess.CompletedProcess(argv, 2, b'', b'No value found at synthetic')
            return subprocess.CompletedProcess(argv, 0, json.dumps({'data': {'data': saved}}).encode(), b'')
        with patch.object(m.subprocess, 'run', side_effect=run):
            first = m.trial_keys('a' * 40, {b'2', b'3'})
            second = m.trial_keys('a' * 40, {b'2', b'3', b'4'})
        self.assertEqual(first[0].private_numbers().private_value, second[0].private_numbers().private_value)
        self.assertEqual(first[1].private_numbers().private_value, second[1].private_numbers().private_value)
        self.assertEqual(second[2], {b'2', b'3'})
        self.assertEqual(writes, 1)

    def test_wrong_source_or_unknown_custody_is_never_adopted(self):
        for data in ({}, {'state': 'foreign'},
                     {'state': 'owned-unfunded-smoke', 'source_sha': 'b' * 40,
                      'owner_key': '1' * 64, 'candidate_key': '2' * 64, 'initial_uids': []}):
            response = subprocess.CompletedProcess([], 0, json.dumps({'data': {'data': data}}).encode(), b'')
            with patch.object(m.subprocess, 'run', return_value=response) as run:
                with self.assertRaisesRegex(RuntimeError, 'owned_trial_custody_scope_conflict'):
                    m.trial_keys('a' * 40, set())
                self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
