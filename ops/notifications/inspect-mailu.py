#!/usr/bin/env python3
"""Revalidate existing disabled portal custody and sender using read-only APIs.

Unlike enrollment, missing custody/account is a failure and never creates anything.
Run via bao-exec --only COOLIFY_WIRE_TOKEN,COOLIFY_URL -- python3 ops/notifications/inspect-mailu.py.
"""
import importlib.util
import json
import os
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('enrollment', Path(__file__).with_name('enroll-mailu.py'))
enrollment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enrollment)


def inspect():
    custody = enrollment.vault_read()
    if not isinstance(custody, dict) or set(custody) != {
        'state', 'smtp_token', 'token_id', 'sender', 'host', 'port', 'authorized_ips'
    }:
        raise RuntimeError('custody_missing_or_unknown')
    if (custody['state'] != 'disabled-staged' or custody['sender'] != enrollment.SENDER or
        custody['host'] != 'mail.cl8y.com' or custody['port'] != 587 or
        custody['authorized_ips'] != enrollment.STAGED_IPS or
        not isinstance(custody['smtp_token'], str) or len(custody['smtp_token']) < 16 or
        not isinstance(custody['token_id'], str) or
        not re.fullmatch(r'[0-9]{1,20}', custody['token_id'])):
        raise RuntimeError('custody_scope_conflict')
    envs = enrollment.request(os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1',
        'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'], '/services/' + enrollment.SERVICE + '/envs')
    controls = [item['value'] for item in envs if item.get('key') == 'API_TOKEN']
    if len(controls) != 1 or not controls[0]:
        raise RuntimeError('mailu_control_unavailable')
    def read(path):
        return enrollment.request('https://mail.cl8y.com/api/v1', controls[0], path)
    user = read('/user/' + enrollment.SENDER)
    token = read('/token/' + custody['token_id'])
    if user.get('comment') != enrollment.COMMENT or any(user.get(key) is not False for key in
        ('enabled', 'global_admin', 'enable_imap', 'enable_pop', 'allow_spoofing', 'forward_enabled', 'reply_enabled')):
        raise RuntimeError('sender_scope_conflict')
    if (token.get('email') != enrollment.SENDER or token.get('comment') != enrollment.COMMENT or
        token.get('AuthorizedIP') != enrollment.STAGED_IPS):
        raise RuntimeError('token_scope_conflict')
    return {'record': 'owned_mailu_disabled_custody_reverified', 'read_only': True,
            'custody_scope_matches': True, 'sender_disabled': True,
            'token_test_net_only': True, 'admin': False, 'auth_attempts': 0, 'sends': 0}


if __name__ == '__main__':
    try:
        print(json.dumps(inspect(), sort_keys=True))
    except Exception:
        print('owned_mailu_custody_unverified_no_changes_no_raw_output')
        raise SystemExit(1) from None
