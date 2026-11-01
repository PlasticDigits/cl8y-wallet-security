#!/usr/bin/env python3
"""Restrict the existing disabled sender token to its verified gateway source.

The exact current noAUTH receiver proof is gateway activation receipt60a9544.
This does not enable the mailbox, inject credentials, authenticate, or send.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

spec = importlib.util.spec_from_file_location('enrollment', Path(__file__).with_name('enroll-mailu.py'))
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
VERIFIED_IPS = ['168.119.120.255/32']
STATE = 'ip-restricted-disabled'


def read_custody():
    result = subprocess.run(['bao-admin', 'read', '-format=json', e.PATH],
                            capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('existing_custody_unavailable')
    result = json.loads(result.stdout)['data']
    version = result['metadata']['version']
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise RuntimeError('custody_version_invalid')
    return result['data'], version


def write_custody(data, version):
    result = subprocess.run(['bao-admin', 'write', '-format=json', e.PATH, '-'],
        input=json.dumps({'options': {'cas': version}, 'data': data}).encode(),
        capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('custody_cas_failed')


def restrict():
    custody, version = read_custody()
    if not isinstance(custody, dict) or set(custody) != {
        'state', 'smtp_token', 'token_id', 'sender', 'host', 'port', 'authorized_ips'
    }:
        raise RuntimeError('existing_custody_schema_conflict')
    expected = e.STAGED_IPS if custody['state'] == 'disabled-staged' else VERIFIED_IPS if custody['state'] == STATE else None
    if (expected is None or custody['authorized_ips'] != expected or
        custody['sender'] != e.SENDER or custody['host'] != 'mail.cl8y.com' or custody['port'] != 587 or
        not isinstance(custody['token_id'], str) or not re.fullmatch(r'[0-9]{1,20}', custody['token_id']) or
        not isinstance(custody['smtp_token'], str) or len(custody['smtp_token']) < 16):
        raise RuntimeError('existing_custody_scope_conflict')
    envs = e.request(os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1',
        'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'], '/services/' + e.SERVICE + '/envs')
    controls = [item['value'] for item in envs if item.get('key') == 'API_TOKEN']
    if len(controls) != 1 or not controls[0]:
        raise RuntimeError('mailu_control_unavailable')
    def mail(path, method='GET', data=None):
        return e.request('https://mail.cl8y.com/api/v1', controls[0], path, method, data)
    token_path = '/token/' + custody['token_id']
    def verify(ips):
        user = mail('/user/' + e.SENDER)
        token = mail(token_path)
        if user.get('comment') != e.COMMENT or any(user.get(key) is not False for key in
            ('enabled', 'global_admin', 'enable_imap', 'enable_pop', 'allow_spoofing', 'forward_enabled', 'reply_enabled')):
            raise RuntimeError('sender_not_owned_disabled_scope')
        if token.get('email') != e.SENDER or token.get('comment') != e.COMMENT or token.get('AuthorizedIP') != ips:
            raise RuntimeError('owned_token_scope_conflict')
    verify(expected)
    if custody['state'] == STATE:
        return receipt(False)
    target = dict(custody, state=STATE, authorized_ips=VERIFIED_IPS)
    try:
        # Mutation intent precedes the API call so a timeout also restores TEST-NET.
        mail(token_path, 'PATCH', {'AuthorizedIP': VERIFIED_IPS})
        verify(VERIFIED_IPS)
        write_custody(target, version)
        actual, actual_version = read_custody()
        if actual != target or actual_version != version + 1:
            raise RuntimeError('custody_readback_conflict')
    except Exception:
        # Fail closed. Compensate only our own exact CAS successor if it exists;
        # never overwrite concurrent custody. The account remains disabled.
        mail(token_path, 'PATCH', {'AuthorizedIP': e.STAGED_IPS})
        actual, actual_version = read_custody()
        if actual == target and actual_version == version + 1:
            write_custody(custody, actual_version)
        verify(e.STAGED_IPS)
        raise RuntimeError('restriction_not_accepted_sender_disabled') from None
    return receipt(True)


def receipt(changed):
    return {'record': 'owned_mailu_ip_restricted_sender_disabled', 'changed': changed,
            'verified_gateway_ip_only': True, 'sender_disabled': True,
            'custody_readback': True, 'token_rotated': False,
            'admin': False, 'auth_attempts': 0, 'sends': 0}


if __name__ == '__main__':
    try:
        print(json.dumps(restrict(), sort_keys=True))
    except Exception:
        print('owned_mailu_ip_restriction_not_accepted_no_raw_output')
        raise SystemExit(1) from None
