#!/usr/bin/env python3
"""Bounded actual portal opt-in and three owned notices, with no SQL or chain use.

Run only in the coordinator's exact-owned-recipient delivery window. Credentials,
ephemeral wallets, verification codes, cookies and message bodies stay in memory.
"""
import argparse
import base64
import datetime as dt
import email
import email.policy
from email.utils import getaddresses
import hashlib
import http.cookiejar
import imaplib
import importlib.util
import json
from pathlib import Path
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('live_smoke', ROOT / 'deploy/live-smoke.py')
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)
ORIGIN = 'https://security.cl8y.com'
RECIPIENT = 'wallet-security-smoke@cl8y.com'
SENDER = 'wallet-security-notices@cl8y.com'
PATH = 'secret/data/groups/cl8y-wallet-security/mailu_smoke'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Portal:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies), NoRedirect())
        self.csrf = None

    def request(self, path, payload=None, expected=200):
        headers = {'Origin': ORIGIN, 'Accept': 'application/json'}
        if self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(ORIGIN + path, headers=headers,
            data=None if payload is None else json.dumps(payload).encode())
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            content = response.read(131073)
            if len(content) > 131072 or response.status != expected:
                raise RuntimeError('portal_response_not_accepted')
        return json.loads(content)

    def prove(self, key, purpose):
        public = key.public_key().public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.CompressedPoint)
        wallet = live.address(public)
        challenge = self.request('/api/v1/auth/challenge', {'address': wallet, 'purpose': purpose})
        document = {'account_number': '0', 'chain_id': '', 'fee': {'amount': [], 'gas': '0'},
                    'memo': '', 'msgs': [{'type': 'sign/MsgSignData', 'value': {
                        'data': base64.b64encode(challenge['message'].encode()).decode(),
                        'signer': wallet}}], 'sequence': '0'}
        encoded = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
        r, signature_s = utils.decode_dss_signature(key.sign(encoded, ec.ECDSA(hashes.SHA256())))
        signature_s = min(signature_s, live.ORDER - signature_s)
        result = self.request('/api/v1/auth/verify', {'id': challenge['id'],
            'public_key': base64.b64encode(public).decode(),
            'signature': base64.b64encode(r.to_bytes(32, 'big') + signature_s.to_bytes(32, 'big')).decode()})
        if purpose == 'login':
            self.csrf = result['csrf_token']
        return result, wallet


def owned_message(raw):
    if not isinstance(raw, bytes) or len(raw) > 8192:
        raise RuntimeError('mail_bound')
    message = email.message_from_bytes(raw, policy=email.policy.default)
    if ([value for _, value in getaddresses(message.get_all('From', []))] != [SENDER] or
        [value for _, value in getaddresses(message.get_all('To', []))] != [RECIPIENT] or
        message.get('Subject') != 'CL8Y wallet security notice'):
        return None
    match = re.fullmatch(r'<([0-9a-f-]{36})@security\.cl8y\.com>', message.get('Message-ID', ''))
    if not match:
        return None
    identifier = str(uuid.UUID(match[1]))
    part = message.get_body(preferencelist=('plain',)) if message.is_multipart() else message
    if part is None or part.get_content_type() != 'text/plain':
        return None
    text = part.get_content().replace('\r\n', '\n').replace('\r', '\n')
    allowed = {ORIGIN + '/#notifications', ORIGIN + '/#timers'}
    if any(url.rstrip(':') not in allowed for url in re.findall(r'https?://[^\s]+', text)):
        return None
    return identifier, text


def imap_uids(connection):
    status, data = connection.uid('search', None, 'ALL')
    if status != 'OK' or len(data) != 1 or not isinstance(data[0], bytes):
        raise RuntimeError('mail_search_not_accepted')
    identifiers = data[0].split()
    if len(identifiers) > 100 or any(not re.fullmatch(rb'[0-9]{1,20}', uid) for uid in identifiers):
        raise RuntimeError('mail_inventory_bound')
    return set(identifiers)


def wait_notice(connection, seen, kind, wallet=None):
    deadline = time.monotonic() + 60
    inspected = 0
    while time.monotonic() < deadline:
        for uid in sorted(imap_uids(connection) - seen, key=int):
            seen.add(uid)
            inspected += 1
            if inspected > 10:
                raise RuntimeError('mail_candidate_bound')
            status, values = connection.uid('fetch', uid, '(BODY.PEEK[]<0.8192>)')
            if status != 'OK':
                raise RuntimeError('mail_fetch_not_accepted')
            bodies = [row[1] for row in values if isinstance(row, tuple) and len(row) == 2]
            if len(bodies) != 1:
                raise RuntimeError('mail_fetch_shape')
            notice = owned_message(bodies[0])
            if notice is None:
                continue
            identifier, text = notice
            if kind == 'verification':
                codes = re.findall(r'(?m)^[0-9a-f]{64}$', text)
                if text.startswith('Confirm your CL8Y email channel') and len(codes) == 1:
                    return identifier, codes[0], text
            elif (text.startswith('Security timer started: ' + kind + '\n') and
                  '\nWallet: ' + wallet + '\n' in text and ORIGIN + '/#timers' in text):
                return identifier, None, text
        time.sleep(2)
    raise RuntimeError('owned_notice_not_received_within_bound')


def mailbox_credential():
    result = subprocess.run(['bao-admin', 'read', '-format=json', PATH], capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('owned_receiver_custody_unavailable')
    data = json.loads(result.stdout)['data']['data']
    if (set(data) != {'state', 'recipient', 'imap_token', 'token_id', 'host', 'port', 'authorized_ips'} or
        data.get('state') != 'enabled-owned-smoke' or data.get('recipient') != RECIPIENT or
        data.get('host') != 'mail.cl8y.com' or data.get('port') != 993 or
        data.get('authorized_ips') != ['222.107.251.38/32'] or
        not isinstance(data.get('imap_token'), str) or len(data['imap_token']) < 16):
        raise RuntimeError('owned_receiver_custody_scope_conflict')
    return data['imap_token']


def trial_keys(source, current_uids):
    """Keep only unfunded trial keys and the initial UID boundary in privateKV.

    This permits recovery of the same owned profile after a bounded failure,
    without creating another verification request inside its destination limit.
    """
    path = 'secret/data/groups/cl8y-wallet-security/mailu_smoke_trial'
    result = subprocess.run(['bao-admin', 'read', '-format=json', path], capture_output=True, timeout=25)
    if result.returncode:
        if b'No value found at' not in result.stderr:
            raise RuntimeError('owned_trial_custody_unavailable')
        data = {'state': 'owned-unfunded-smoke', 'source_sha': source,
                'owner_key': format(ec.generate_private_key(ec.SECP256K1()).private_numbers().private_value, '064x'),
                'candidate_key': format(ec.generate_private_key(ec.SECP256K1()).private_numbers().private_value, '064x'),
                'initial_uids': sorted(uid.decode('ascii') for uid in current_uids)}
        stored = subprocess.run(['bao-admin', 'write', '-format=json', path, '-'],
            input=json.dumps({'options': {'cas': 0}, 'data': data}).encode(),
            capture_output=True, timeout=25)
        if stored.returncode:
            raise RuntimeError('owned_trial_custody_cas_failed')
        result = subprocess.run(['bao-admin', 'read', '-format=json', path], capture_output=True, timeout=25)
        if result.returncode or json.loads(result.stdout)['data']['data'] != data:
            raise RuntimeError('owned_trial_custody_readback_failed')
    else:
        data = json.loads(result.stdout)['data']['data']
    if (not isinstance(data, dict) or set(data) != {'state', 'source_sha', 'owner_key', 'candidate_key', 'initial_uids'} or
        data['state'] != 'owned-unfunded-smoke' or data['source_sha'] != source or
        any(not isinstance(data[key], str) or not re.fullmatch(r'[0-9a-f]{64}', data[key])
            for key in ('owner_key', 'candidate_key')) or
        not isinstance(data['initial_uids'], list) or len(data['initial_uids']) > 100 or
        any(not isinstance(uid, str) or not re.fullmatch(r'[0-9]{1,20}', uid) for uid in data['initial_uids'])):
        raise RuntimeError('owned_trial_custody_scope_conflict')
    return (ec.derive_private_key(int(data['owner_key'], 16), ec.SECP256K1()),
            ec.derive_private_key(int(data['candidate_key'], 16), ec.SECP256K1()),
            {uid.encode('ascii') for uid in data['initial_uids']})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sha', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.sha):
        raise RuntimeError('exact_source_required')
    portal = Portal()
    health = portal.request('/healthz')
    status = portal.request('/api/v1/status')
    if (health.get('source_sha') != args.sha or health.get('migration') != 6 or
        status.get('source_sha') != args.sha or not status['notifications']['email_ready'] or
        not status.get('worker') or status['worker'].get('source_sha') != args.sha):
        raise RuntimeError('coordinated_live_source_or_readiness_mismatch')
    token = mailbox_credential()
    connection = imaplib.IMAP4_SSL('mail.cl8y.com', 993, ssl_context=ssl.create_default_context(), timeout=15)
    proposal_id = None
    try:
        if connection.sock.getpeername()[0] != '167.233.253.175':
            raise RuntimeError('fixed_mailu_endpoint_mismatch')
        connection.login(RECIPIENT, token)
        del token
        if connection.select('INBOX', readonly=True)[0] != 'OK':
            raise RuntimeError('owned_mailbox_select_failed')
        owner, candidate, seen = trial_keys(args.sha, imap_uids(connection))
        _, wallet = portal.prove(owner, 'login')
        me = portal.request('/api/v1/me')
        if not me['authenticated']:
            raise RuntimeError('owned_login_failed')
        contacts = me['contacts']
        if not contacts:
            queued = portal.request('/api/v1/contacts/email', {'address': RECIPIENT})
            contact_id = str(uuid.UUID(queued['id']))
            if queued.get('queued') is not True or queued.get('sent') is not False:
                raise RuntimeError('verification_queue_receipt_failed')
            verified = False
        else:
            # Only this private generated key ever mutates the dedicated profile.
            # Never create a second contact to recover from a bounded timeout.
            if len(contacts) != 1 or contacts[0].get('kind') != 'email':
                raise RuntimeError('owned_profile_contact_scope_conflict')
            contact_id = str(uuid.UUID(contacts[0]['id']))
            verified = contacts[0]['status'] == 'verified'
        verification_id, code, _ = wait_notice(connection, seen, 'verification')
        print('owned_delivery_smoke_stage verification_received=true', flush=True)
        if not verified:
            confirmed = portal.request('/api/v1/contacts/email/verify', {'token': code})
            if confirmed.get('verified') is not True or confirmed.get('status') != 'verified':
                raise RuntimeError('owned_double_optin_failed')
        portal.request('/api/v1/contacts/email/verify', {'token': code}, expected=400)
        del code
        _, candidate_wallet = portal.prove(candidate, 'add_wallet')
        assignments = portal.request('/api/v1/me')['assignments']
        if not assignments:
            proposal = portal.request('/api/v1/assignments', {'candidate_wallet': candidate_wallet, 'role': 'notification'})
        else:
            if len(assignments) != 1 or assignments[0]['candidate_wallet'] != candidate_wallet or assignments[0]['role'] != 'notification':
                raise RuntimeError('owned_profile_assignment_scope_conflict')
            proposal = assignments[0]
        proposal_id = str(uuid.UUID(proposal['id']))
        if proposal['delay_seconds'] < 86400:
            raise RuntimeError('owned_timer_delay_failed')
        if not proposal.get('accepted_at') and proposal.get('status') != 'cancelled':
            portal.prove(candidate, 'assignment:' + proposal_id)
        timer_id, _, timer = wait_notice(connection, seen, 'assignment_start', wallet)
        print('owned_delivery_smoke_stage timer_received=true', flush=True)
        notice_deadline = re.search(r'(?m)^Deadline: (.+)$', timer)
        if not notice_deadline or dt.datetime.fromisoformat(notice_deadline[1].replace('Z', '+00:00')) != dt.datetime.fromisoformat(proposal['executable_at'].replace('Z', '+00:00')):
            raise RuntimeError('owned_timer_deadline_mismatch')
        portal.request('/api/v1/assignments/' + proposal_id + '/cancel', {})
        before_removal = portal.request('/api/v1/me')
        prior_removal = next(item for item in before_removal['contacts'] if item['id'] == contact_id).get('removal_at')
        was_removal_pending = prior_removal is not None
        removal = portal.request('/api/v1/contacts/' + contact_id + '/remove', {})
        expected_removal = prior_removal if was_removal_pending else removal.get('removal_at')
        removal_id, _, _ = wait_notice(connection, seen, 'contact_removal_start', wallet)
        me = portal.request('/api/v1/me')
        contact = next(item for item in me['contacts'] if item['id'] == contact_id)
        if (contact.get('status') != 'verified' or not contact.get('removal_at') or
            contact['removal_at'] != expected_removal or
            (not was_removal_pending and dt.datetime.fromisoformat(contact['removal_at'].replace('Z', '+00:00')) <
             dt.datetime.fromisoformat(before_removal['server_time'].replace('Z', '+00:00')) + dt.timedelta(days=1))):
            raise RuntimeError('old_verified_channel_not_retained')
        identifiers = [verification_id, timer_id, removal_id]
        if len(set(identifiers)) != 3:
            raise RuntimeError('distinct_owned_messages_required')
        print(json.dumps({'record': 'owned_portal_notification_delivery_pass', 'source_sha': args.sha,
            'migration': 6, 'owned_wallet_optin': True, 'verification_received': True,
            'one_use_code_replay_denied': True, 'dangerous_timer_received': True,
            'timer_deadline_matches': True, 'old_contact_removal_warning_received': True,
            'old_verified_channel_retained': True, 'distinct_owned_messages': 3,
            'message_id_sha256': [hashlib.sha256(value.encode()).hexdigest() for value in identifiers],
            'imap_hostname_verified': True, 'workstation_ip_restriction_accepted': True,
            'raw_payloads_or_addresses_emitted': False, 'direct_sql_writes': 0, 'chain_transactions': 0}, sort_keys=True))
    finally:
        if portal.csrf:
            if proposal_id:
                try: portal.request('/api/v1/assignments/' + proposal_id + '/cancel', {})
                except Exception: pass
            try: portal.request('/api/v1/auth/logout', {})
            except Exception: pass
        try: connection.logout()
        except Exception: pass


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('owned_delivery_smoke_not_accepted_no_raw_output', flush=True)
        raise SystemExit(1) from None
