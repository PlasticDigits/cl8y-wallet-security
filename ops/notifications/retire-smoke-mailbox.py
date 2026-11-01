#!/usr/bin/env python3
"""Disable only the owned smoke receiver and revoke its exact account token.

Run after independent backup acceptance. No sender, portal, database, outbox,
profile, checkpoint, mailbox contents or other account is changed or deleted.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error

spec = importlib.util.spec_from_file_location('smoke_enrollment', Path(__file__).with_name('enroll-smoke-mailbox.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
e = s.e
FINAL = 'disabled-smoke-complete'


def read():
    result = subprocess.run(['bao-admin', 'read', '-format=json', s.PATH], capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('smoke_custody_unavailable')
    value = json.loads(result.stdout)['data']
    version = value['metadata']['version']
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise RuntimeError('smoke_custody_version_invalid')
    return value['data'], version


def retire():
    data, version = read()
    if not isinstance(data, dict) or data.get('state') not in ('enabled-owned-smoke', FINAL):
        raise RuntimeError('smoke_custody_state_conflict')
    complete = data['state'] == FINAL
    expected = {'state', 'recipient', 'token_id', 'host', 'port', 'authorized_ips'} | (
        {'token_revoked'} if complete else {'imap_token'})
    if (set(data) != expected or data['recipient'] != s.RECIPIENT or data['host'] != 'mail.cl8y.com' or
        data['port'] != 993 or data['authorized_ips'] != s.IPS or
        not isinstance(data['token_id'], str) or not re.fullmatch(r'[0-9]{1,20}', data['token_id']) or
        (complete and data['token_revoked'] is not True) or
        (not complete and (not isinstance(data['imap_token'], str) or len(data['imap_token']) < 16))):
        raise RuntimeError('smoke_custody_scope_conflict')
    envs = e.request(os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1',
        'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'], '/services/' + e.SERVICE + '/envs')
    controls = [item['value'] for item in envs if item.get('key') == 'API_TOKEN']
    if len(controls) != 1 or not controls[0]:
        raise RuntimeError('mailu_control_unavailable')
    def mail(path, method='GET', payload=None):
        return e.request('https://mail.cl8y.com/api/v1', controls[0], path, method, payload)
    user_path = '/user/' + s.RECIPIENT
    token_path = '/token/' + data['token_id']
    def user_scope():
        user = mail(user_path)
        if (user.get('comment') != s.COMMENT or user.get('quota_bytes') != 10485760 or
            user.get('enable_imap') is not True or not isinstance(user.get('enabled'), bool) or
            any(user.get(key) is not False for key in
                ('global_admin', 'enable_pop', 'allow_spoofing', 'forward_enabled', 'reply_enabled'))):
            raise RuntimeError('smoke_user_scope_conflict')
        return user
    def token_scope():
        try:
            token = mail(token_path)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise RuntimeError('smoke_token_lookup_failed') from None
        if (token.get('email') != s.RECIPIENT or token.get('comment') != s.COMMENT or
            token.get('AuthorizedIP') != s.IPS):
            raise RuntimeError('smoke_token_scope_conflict')
        return token
    user, token = user_scope(), token_scope()
    if complete:
        if user['enabled'] is not False or token is not None:
            raise RuntimeError('completed_smoke_scope_drift')
        return receipt(False)
    if user['enabled'] is True:
        mail(user_path, 'PATCH', {'enabled': False})
    if user_scope()['enabled'] is not False:
        raise RuntimeError('smoke_disable_readback_failed')
    if token is not None:
        # Recheck immediately before deletion; never revoke another token identity.
        token_scope()
        mail(token_path, 'DELETE')
    if token_scope() is not None:
        raise RuntimeError('smoke_revocation_readback_failed')
    final = {key: value for key, value in data.items() if key != 'imap_token'}
    final.update(state=FINAL, token_revoked=True)
    result = subprocess.run(['bao-admin', 'write', '-format=json', s.PATH, '-'],
        input=json.dumps({'options': {'cas': version}, 'data': final}).encode(),
        capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('smoke_retirement_cas_failed_disabled_and_revoked')
    actual, actual_version = read()
    if actual != final or actual_version != version + 1:
        raise RuntimeError('smoke_retirement_custody_readback_failed')
    return receipt(True)


def receipt(changed):
    return {'record': 'owned_smoke_receiver_retired', 'changed': changed,
            'receiver_disabled': True, 'owned_receiver_token_revoked': True,
            'current_custody_credential_removed': True, 'custody_readback': True,
            'sender_not_modified': True, 'portal_or_database_changes': False,
            'outbox_profile_checkpoint_preserved': True, 'smtp_imap_auth_attempts': 0, 'sends': 0}


if __name__ == '__main__':
    try:
        print(json.dumps(retire(), sort_keys=True))
    except Exception:
        print('owned_smoke_receiver_retirement_not_accepted_no_raw_output')
        raise SystemExit(1) from None
