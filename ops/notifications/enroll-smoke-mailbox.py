#!/usr/bin/env python3
"""Prepare a disabled dedicated owned receiver; never adopt an existing mailbox.

No login, sender enablement, forward, message or portal setting is performed.
The separate IMAP token is stored only in exact privateKV through stdin.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import urllib.error

spec = importlib.util.spec_from_file_location('enrollment', Path(__file__).with_name('enroll-mailu.py'))
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
RECIPIENT = 'wallet-security-smoke@cl8y.com'
PATH = 'secret/data/groups/cl8y-wallet-security/mailu_smoke'
COMMENT = 'cl8y-wallet-security owned-only notification smoke receiver issue 3'
# Exact workstation public interface source; acceptance still requires an actual
# bounded TLS/IMAP login after independent activation review. No NAT is inferred.
IPS = ['222.107.251.38/32']


def read_custody():
    result = subprocess.run(['bao-admin', 'read', '-format=json', PATH],
                            capture_output=True, timeout=25)
    if result.returncode:
        if b'No value found at' in result.stderr:
            return None
        raise RuntimeError('smoke_custody_unavailable')
    return json.loads(result.stdout)['data']['data']


def prepare():
    custody = read_custody()
    envs = e.request(os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1',
        'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'], '/services/' + e.SERVICE + '/envs')
    controls = [item['value'] for item in envs if item.get('key') == 'API_TOKEN']
    if len(controls) != 1 or not controls[0]:
        raise RuntimeError('mailu_control_unavailable')
    def mail(path, method='GET', data=None):
        return e.request('https://mail.cl8y.com/api/v1', controls[0], path, method, data)
    try:
        user = mail('/user/' + RECIPIENT)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise RuntimeError('smoke_mailbox_lookup_failed') from None
        user = None
    created = False
    if custody is None:
        if user is not None:
            raise RuntimeError('preexisting_smoke_mailbox_not_adopted')
        mail('/user', 'POST', dict(email=RECIPIENT, raw_password=secrets.token_urlsafe(48),
            comment=COMMENT, displayed_name='CL8Y owned notification smoke', quota_bytes=10485760,
            global_admin=False, enabled=False, enable_imap=True, enable_pop=False,
            allow_spoofing=False, forward_enabled=False, reply_enabled=False))
        token = mail('/token', 'POST', dict(email=RECIPIENT, comment=COMMENT, AuthorizedIP=IPS))
        token_id = str(token['id'])
        if not re.fullmatch(r'[0-9]{1,20}', token_id):
            raise RuntimeError('smoke_token_identity_invalid')
        data = {'state': 'disabled-owned-smoke', 'recipient': RECIPIENT,
                'imap_token': token['token'], 'token_id': token_id,
                'host': 'mail.cl8y.com', 'port': 993, 'authorized_ips': IPS}
        result = subprocess.run(['bao-admin', 'write', '-format=json', PATH, '-'],
            input=json.dumps({'options': {'cas': 0}, 'data': data}).encode(),
            capture_output=True, timeout=25)
        if result.returncode:
            # Revoke only the token just created. The new mailbox stays disabled.
            mail('/token/' + token_id, 'DELETE')
            raise RuntimeError('smoke_custody_failed_account_disabled')
        custody = read_custody()
        if custody != data:
            raise RuntimeError('smoke_custody_readback_failed')
        user = mail('/user/' + RECIPIENT)
        created = True
    if (not isinstance(custody, dict) or set(custody) != {
        'state', 'recipient', 'imap_token', 'token_id', 'host', 'port', 'authorized_ips'
    } or custody.get('state') != 'disabled-owned-smoke' or custody.get('recipient') != RECIPIENT or
        custody.get('host') != 'mail.cl8y.com' or custody.get('port') != 993 or
        custody.get('authorized_ips') != IPS or not isinstance(custody.get('imap_token'), str) or
        len(custody['imap_token']) < 16 or not isinstance(custody.get('token_id'), str) or
        not re.fullmatch(r'[0-9]{1,20}', custody['token_id'])):
        raise RuntimeError('smoke_custody_scope_conflict')
    if (not isinstance(user, dict) or user.get('comment') != COMMENT or
        user.get('quota_bytes') != 10485760 or user.get('enable_imap') is not True or
        any(user.get(key) is not False for key in
            ('enabled', 'global_admin', 'enable_pop', 'allow_spoofing', 'forward_enabled', 'reply_enabled'))):
        raise RuntimeError('smoke_mailbox_scope_conflict')
    token = mail('/token/' + custody['token_id'])
    if token.get('email') != RECIPIENT or token.get('comment') != COMMENT or token.get('AuthorizedIP') != IPS:
        raise RuntimeError('smoke_token_scope_conflict')
    return {'record': 'owned_smoke_mailbox_disabled_prepared', 'created': created,
            'mailbox_disabled': True, 'imap_scope': True, 'workstation_ip_only': True,
            'quota_bytes': 10485760, 'custody_readback': True, 'admin': False,
            'forwarding': False, 'auth_attempts': 0, 'sends': 0}


if __name__ == '__main__':
    try:
        print(json.dumps(prepare(), sort_keys=True))
    except Exception:
        print('owned_smoke_mailbox_preparation_not_accepted_no_raw_output')
        raise SystemExit(1) from None
