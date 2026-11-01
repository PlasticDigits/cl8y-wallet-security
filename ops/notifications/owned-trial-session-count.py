"""Workstation-only read-only identity resolver and parameterized session counter.

No CLI and no output. Never print the resolved anchor or pass it through argv,
logs or a dotenv. A caller's private query bridge must preserve SQL parameters.
The restored DB must be queried before any scratch-session invalidation.
"""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

SOURCE = '4fbe03977337925f6185b393a8aa39437095b097'
PATH = 'secret/data/groups/cl8y-wallet-security/mailu_smoke_trial'
spec = importlib.util.spec_from_file_location('live_smoke', Path(__file__).resolve().parents[2] / 'deploy/live-smoke.py')
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


def owned_anchor():
    result = subprocess.run(['bao-admin', 'read', '-format=json', PATH], capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('existing_owned_trial_custody_unavailable')
    data = json.loads(result.stdout)['data']['data']
    if (not isinstance(data, dict) or set(data) != {'state', 'source_sha', 'owner_key', 'candidate_key', 'initial_uids'} or
        data['state'] != 'owned-unfunded-smoke' or data['source_sha'] != SOURCE or
        any(not isinstance(data[key], str) or not re.fullmatch(r'[0-9a-f]{64}', data[key])
            for key in ('owner_key', 'candidate_key')) or
        not isinstance(data['initial_uids'], list) or len(data['initial_uids']) > 100 or
        any(not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,20}', value) for value in data['initial_uids'])):
        raise RuntimeError('existing_owned_trial_custody_scope_conflict')
    key = ec.derive_private_key(int(data['owner_key'], 16), ec.SECP256K1())
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return live.address(public)


def active_sessions(query):
    """query(sql, parameters) returns rows over an existing private DB channel."""
    anchor = owned_anchor()
    rows = query('''SELECT
        (SELECT count(*) FROM profiles WHERE anchor_wallet=%s),
        (SELECT count(*) FROM sessions s JOIN profiles p ON p.id=s.profile_id
         WHERE p.anchor_wallet=%s AND s.expires_at>now())''', (anchor, anchor))
    if (not isinstance(rows, (tuple, list)) or len(rows) != 1 or len(rows[0]) != 2 or
        any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in rows[0]) or
        rows[0][0] not in (0, 1) or rows[0][0] == 0 and rows[0][1] != 0):
        raise RuntimeError('owned_trial_session_metadata_invalid')
    return {'profile_present': rows[0][0] == 1, 'active_session_count': rows[0][1]}
