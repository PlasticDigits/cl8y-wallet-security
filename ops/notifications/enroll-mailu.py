#!/usr/bin/env python3
"""Prepare a disabled dedicated Mailu sender and store only its scoped token in OpenBao.
Run via bao-exec --only COOLIFY_WIRE_TOKEN,COOLIFY_URL -- python3 ops/notifications/enroll-mailu.py.
This command never enables a sender, changes portal runtime or sends mail.
"""
import json
import os
import secrets
import subprocess
import urllib.error
import urllib.request

SERVICE = 'kzcsybgqrftglacdf3j8bfk1'
SENDER = 'wallet-security-notices@cl8y.com'
PATH = 'secret/data/groups/cl8y-wallet-security/mailu_smtp'
COMMENT = 'cl8y-wallet-security notification sender staged issue 3'
# Non-routable documentation range, deliberately unusable until reviewed route proof.
STAGED_IPS = ['192.0.2.1/32']

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def request(base, token, path, method='GET', data=None):
    req = urllib.request.Request(base + path, method=method,
        headers={'Authorization': token, 'Accept': 'application/json', 'Content-Type': 'application/json'},
        data=None if data is None else json.dumps(data).encode())
    with OPENER.open(req, timeout=15) as response:
        content = response.read(2_000_001)
        if len(content) > 2_000_000:
            raise RuntimeError('response_bound')
        return json.loads(content) if content else None

def vault_read():
    result = subprocess.run(['bao-admin', 'read', '-format=json', PATH],
        capture_output=True, timeout=25)
    if result.returncode:
        # Distinguish absent data from authentication/transport failure, without printing it.
        if b'No value found at' in result.stderr:
            return None
        raise RuntimeError('vault_read_failed')
    return json.loads(result.stdout)['data']['data']

def prepare():
    existing = vault_read()
    coolify = os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1'
    envs = request(coolify, 'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'], '/services/' + SERVICE + '/envs')
    control = next(item['value'] for item in envs if item.get('key') == 'API_TOKEN')
    def mail(path, method='GET', data=None):
        return request('https://mail.cl8y.com/api/v1', control, path, method, data)
    try:
        user = mail('/user/' + SENDER)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise RuntimeError('mailu_read_failed') from None
        user = None
    if existing:
        if existing.get('state') != 'disabled-staged' or not user:
            raise RuntimeError('existing_state_conflict')
        token_id = existing['token_id']
    else:
        if user:
            raise RuntimeError('sender_exists_without_owned_custody')
        mail('/user', 'POST', dict(email=SENDER, raw_password=secrets.token_urlsafe(48),
            comment=COMMENT, displayed_name='CL8Y wallet security', quota_bytes=10485760,
            global_admin=False, enabled=False, enable_imap=False, enable_pop=False,
            allow_spoofing=False, forward_enabled=False, reply_enabled=False))
        scoped = mail('/token', 'POST', dict(email=SENDER, comment=COMMENT, AuthorizedIP=STAGED_IPS))
        token_id = str(scoped['id'])
        payload = {'options': {'cas': 0}, 'data': {'state': 'disabled-staged',
            'smtp_token': scoped['token'], 'token_id': token_id,
            'sender': SENDER, 'host': 'mail.cl8y.com', 'port': 587,
            'authorized_ips': STAGED_IPS}}
        result = subprocess.run(['bao-admin', 'write', '-format=json', PATH, '-'],
            input=json.dumps(payload).encode(), capture_output=True, timeout=25)
        if result.returncode:
            # Revoke only this newly minted credential; never modify unrelated users/tokens.
            mail('/token/' + token_id, 'DELETE')
            raise RuntimeError('vault_store_failed_sender_remains_disabled')
        existing = vault_read()
        if existing != payload['data']:
            raise RuntimeError('vault_readback_failed')
        user = mail('/user/' + SENDER)
    if not token_id.isdecimal() or len(token_id) > 20:
        raise RuntimeError('token_identity_invalid')
    token = mail('/token/' + token_id)
    if user.get('comment') != COMMENT or any(user.get(k) is not False for k in
        ('enabled', 'global_admin', 'enable_imap', 'enable_pop', 'allow_spoofing', 'forward_enabled', 'reply_enabled')):
        raise RuntimeError('sender_scope_mismatch')
    if token.get('email') != SENDER or token.get('comment') != COMMENT or token.get('AuthorizedIP') != STAGED_IPS:
        raise RuntimeError('token_scope_mismatch')
    print('mailu_sender_staged disabled=true admin=false spoofing=false imap=false pop=false token_ip_staged=true vault_readback=true sends=0')

if __name__ == '__main__':
    try:
        prepare()
    except Exception:
        # All API/Vault error bodies and exception text may contain credentials or PII.
        print('mailu_enrollment_failed_no_activation', flush=True)
        raise SystemExit(1) from None
