#!/usr/bin/env python3
"""Bounded HTTPS smoke with ephemeral, unfunded, owned wallets and no contacts.

Requires the workstation's existing cryptography package. Never prints addresses,
private keys, signatures, cookies, CSRF tokens or response bodies containing them.
"""
import argparse
import base64
import hashlib
import http.cookiejar
import json
import time
import urllib.error
import urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ORIGIN = 'https://security.cl8y.com'
ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)


def address(public):
    raw = hashlib.new('ripemd160', hashlib.sha256(public).digest()).digest()
    values, acc, bits = [], 0, 0
    for byte in raw:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    if bits:
        values.append((acc << (5 - bits)) & 31)
    hrp = 'terra'
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    check = 1
    for value in expanded + values + [0] * 6:
        top = check >> 25
        check = ((check & 0x1ffffff) << 5) ^ value
        for index, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> index) & 1:
                check ^= generator
    check ^= 1
    values += [(check >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + '1' + ''.join('qpzry9x8gf2tvdw0s3jn54khce6mua7l'[value] for value in values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--migration', type=int, required=True)
    args = parser.parse_args()
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    csrf = None
    checks = {}

    def request(path, payload=None, headers=None, expected=200):
        values = {'Origin': ORIGIN, 'Accept': 'application/json'}
        if csrf:
            values['X-CSRF-Token'] = csrf
        values.update(headers or {})
        if payload is not None:
            values['Content-Type'] = 'application/json'
        call = urllib.request.Request(ORIGIN + path, headers=values,
            data=None if payload is None else json.dumps(payload).encode())
        try:
            with opener.open(call, timeout=15) as response:
                status = response.status
                body = response.read()
                content_type = response.headers.get('Content-Type', '')
        except urllib.error.HTTPError as error:
            status, body, content_type = error.code, error.read(), error.headers.get('Content-Type', '')
        if status != expected:
            raise SystemExit('smoke failed: ' + path.split('?')[0] + ' HTTP ' + str(status))
        return json.loads(body) if 'application/json' in content_type else body

    def prove(key, purpose):
        public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        wallet = address(public)
        challenge = request('/api/v1/auth/challenge', {'address': wallet, 'purpose': purpose})
        document = {'account_number': '0', 'chain_id': '', 'fee': {'amount': [], 'gas': '0'}, 'memo': '',
                    'msgs': [{'type': 'sign/MsgSignData', 'value': {'data': base64.b64encode(challenge['message'].encode()).decode(), 'signer': wallet}}], 'sequence': '0'}
        encoded = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
        r, s = utils.decode_dss_signature(key.sign(encoded, ec.ECDSA(hashes.SHA256())))
        s = min(s, ORDER - s)
        proof = {'id': challenge['id'], 'public_key': base64.b64encode(public).decode(),
                 'signature': base64.b64encode(r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).decode()}
        return request('/api/v1/auth/verify', proof), proof, wallet

    html = request('/')
    checks['static_frontend'] = isinstance(html, bytes) and b'<script' in html and b'/assets/' in html
    health = request('/healthz')
    checks['health_exact_sha'] = health.get('source_sha') == args.sha
    checks['migration_exact'] = health.get('migration') == args.migration
    checks['anonymous_session'] = request('/api/v1/me').get('authenticated') is False
    before = request('/api/v1/status')
    checks['delivery_disabled'] = before['notifications']['delivery_enabled'] is False
    checks['worker_exact_sha'] = bool(before.get('worker')) and before['worker']['source_sha'] == args.sha
    checks['chain_unconfigured'] = before['chain'].get('status') in ('unavailable', 'unconfigured')
    owner = ec.generate_private_key(ec.SECP256K1())
    result, replay, _ = prove(owner, 'login')
    csrf = result['csrf_token']
    checks['owned_wallet_login'] = request('/api/v1/me').get('authenticated') is True
    checks['secure_cookie'] = all(cookie.secure and cookie.path == '/' and cookie.has_nonstandard_attr('HttpOnly') for cookie in cookies)
    request('/api/v1/auth/verify', replay, expected=401)
    checks['challenge_replay_denied'] = True
    candidate = ec.generate_private_key(ec.SECP256K1())
    _, _, candidate_address = prove(candidate, 'add_wallet')
    proposal = request('/api/v1/assignments', {'candidate_wallet': candidate_address, 'role': 'guardian'})
    checks['minimum_assignment_delay'] = proposal['delay_seconds'] >= 86400
    prove(candidate, 'assignment:' + proposal['id'])
    me = request('/api/v1/me')
    checks['dual_wallet_proof'] = len(me['wallets']) == 2 and any(item['id'] == proposal['id'] and item['status'] == 'pending' for item in me['assignments'])
    request('/api/v1/assignments/' + proposal['id'] + '/cancel', {})
    checks['pending_cancellation'] = any(item['id'] == proposal['id'] and item['status'] == 'cancelled' for item in request('/api/v1/me')['assignments'])
    checks['no_contact_destinations'] = not me['contacts']
    request('/api/v1/auth/logout', {})
    checks['logout'] = request('/api/v1/me').get('authenticated') is False
    # One bounded wait covers a full 15-second worker heartbeat interval.
    time.sleep(17)
    after = request('/api/v1/status')
    checks['worker_heartbeat_advances'] = bool(after.get('worker')) and after['worker']['source_sha'] == args.sha and after['worker']['last_seen'] > before['worker']['last_seen']
    print(json.dumps({'origin': ORIGIN, 'source_sha': args.sha, 'migration': health['migration'],
                      'server_time': health['server_time'], 'checks': checks}, sort_keys=True))
    if not all(checks.values()):
        raise SystemExit('one or more live smoke assertions failed')


if __name__ == '__main__':
    main()
