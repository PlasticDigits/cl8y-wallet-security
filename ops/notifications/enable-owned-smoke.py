#!/usr/bin/env python3
"""Enable only the two owned scoped accounts for the coordinated sandbox trial.

No portal settings, token rotation, SMTP/IMAP authentication or messages occur.
The coordinator must separately enforce the exact worker recipient allowlist.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

e = module('sender_enrollment', 'enroll-mailu.py')
s = module('smoke_enrollment', 'enroll-smoke-mailbox.py')
TARGET = 'enabled-owned-smoke'
SCOPES = (
    dict(path=e.PATH, address=e.SENDER, comment=e.COMMENT, identity='sender',
         token_key='smtp_token', address_key='sender', port=587, imap=False,
         ips=['168.119.120.255/32'], initial='ip-restricted-disabled'),
    dict(path=s.PATH, address=s.RECIPIENT, comment=s.COMMENT, identity='receiver',
         token_key='imap_token', address_key='recipient', port=993, imap=True,
         ips=s.IPS, initial='disabled-owned-smoke'),
)


def read(path):
    result = subprocess.run(['bao-admin', 'read', '-format=json', path], capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('owned_custody_unavailable')
    data = json.loads(result.stdout)['data']
    version = data['metadata']['version']
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise RuntimeError('owned_custody_version_invalid')
    return data['data'], version


def write(path, data, version):
    result = subprocess.run(['bao-admin', 'write', '-format=json', path, '-'],
        input=json.dumps({'options': {'cas': version}, 'data': data}).encode(),
        capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('owned_custody_cas_failed')


def enable():
    envs = e.request(os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1',
        'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'], '/services/' + e.SERVICE + '/envs')
    controls = [item['value'] for item in envs if item.get('key') == 'API_TOKEN']
    if len(controls) != 1 or not controls[0]:
        raise RuntimeError('mailu_control_unavailable')
    def mail(path, method='GET', data=None):
        return e.request('https://mail.cl8y.com/api/v1', controls[0], path, method, data)
    def verify(scope, data, enabled):
        user = mail('/user/' + scope['address'])
        token = mail('/token/' + data['token_id'])
        if (user.get('comment') != scope['comment'] or user.get('quota_bytes') != 10485760 or
            user.get('enabled') is not enabled or user.get('enable_imap') is not scope['imap'] or
            any(user.get(key) is not False for key in
                ('global_admin', 'enable_pop', 'allow_spoofing', 'forward_enabled', 'reply_enabled'))):
            raise RuntimeError('owned_account_scope_conflict')
        if (token.get('email') != scope['address'] or token.get('comment') != scope['comment'] or
            token.get('AuthorizedIP') != scope['ips']):
            raise RuntimeError('owned_token_scope_conflict')
    originals = []
    for scope in SCOPES:
        data, version = read(scope['path'])
        if (not isinstance(data, dict) or set(data) != {
            'state', scope['address_key'], scope['token_key'], 'token_id', 'host', 'port', 'authorized_ips'
        } or data.get('state') not in (scope['initial'], TARGET) or
            data.get(scope['address_key']) != scope['address'] or data.get('host') != 'mail.cl8y.com' or
            data.get('port') != scope['port'] or data.get('authorized_ips') != scope['ips'] or
            not isinstance(data.get('token_id'), str) or not re.fullmatch(r'[0-9]{1,20}', data['token_id']) or
            not isinstance(data.get(scope['token_key']), str) or len(data[scope['token_key']]) < 16):
            raise RuntimeError('owned_custody_scope_conflict')
        verify(scope, data, data['state'] == TARGET)
        originals.append((scope, data, version))
    changed = 0
    try:
        for scope, data, version in originals:
            if data['state'] == TARGET:
                continue
            mail('/user/' + scope['address'], 'PATCH', {'enabled': True})
            verify(scope, data, True)
            target = dict(data, state=TARGET)
            write(scope['path'], target, version)
            actual, actual_version = read(scope['path'])
            if actual != target or actual_version != version + 1:
                raise RuntimeError('owned_custody_readback_conflict')
            changed += 1
    except Exception:
        # Disable both exact preverified owned accounts on partial failure. Only
        # compensate our own exact custody successors, never concurrent edits.
        compensated = True
        for scope, data, version in originals:
            try:
                mail('/user/' + scope['address'], 'PATCH', {'enabled': False})
                verify(scope, data, False)
                actual, actual_version = read(scope['path'])
                if actual == dict(data, state=TARGET) and actual_version == version + 1:
                    write(scope['path'], dict(data, state=scope['initial']), actual_version)
            except Exception:
                compensated = False
        raise RuntimeError('owned_smoke_enablement_failed_closed' if compensated else
                           'owned_smoke_enablement_requires_reconciliation') from None
    return {'record': 'owned_mailu_accounts_enabled_for_sandbox', 'accounts_changed': changed,
            'sender_enabled': True, 'receiver_enabled': True, 'custody_readback': True,
            'token_ips_unchanged': True, 'credentials_rotated': False, 'admin': False,
            'portal_changes': False, 'auth_attempts': 0, 'sends': 0}


if __name__ == '__main__':
    try:
        print(json.dumps(enable(), sort_keys=True))
    except Exception:
        print('owned_smoke_enablement_not_accepted_no_raw_output')
        raise SystemExit(1) from None
