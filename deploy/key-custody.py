#!/usr/bin/env python3
"""Escrow the unchanged portal contact key and an age recovery identity.

Operator-only: use bao-exec with COOLIFY_WIRE_TOKEN,COOLIFY_URL. Credentials
remain in process memory/TLS requests; no credential arguments or local files.
Existing identity-scoped OpenBao ACLs and entity lookup determine the namespace.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True)
    parser.add_argument('--sha', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[a-z0-9]{20,32}', args.app) or not re.fullmatch('[0-9a-f]{40}', args.sha):
        parser.error('invalid resource/source identifier')
    base = os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1/applications/' + args.app

    def coolify(suffix=''):
        request = urllib.request.Request(base + suffix, headers={
            'Authorization': 'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'], 'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            error.read()
            raise SystemExit('Coolify custody read failed HTTP ' + str(error.code)) from None

    application = coolify()
    if application.get('name') != 'cl8y-wallet-security' or application.get('git_commit_sha') != args.sha:
        raise SystemExit('Portal resource/source identity differs')
    envs = {item['key']: item for item in coolify('/envs') if not item.get('is_preview')}
    contact_key = envs.get('CONTACT_ENCRYPTION_KEY', {}).get('value') or ''
    if not re.fullmatch('[0-9a-f]{64}', contact_key):
        raise SystemExit('Canonical protected contact key is absent or invalid')
    sys.path.insert(0, '/home/answorld/openbao-ops')
    from agent_secret.client import connect, SecretError
    connection = {**os.environ, 'SECRET_FORCE_DIRECT': '1', 'SECRET_ADDR': 'https://10.10.0.4:8200',
                  'SECRET_CACERT': str(Path.home() / '.config/openbao/ca.crt'),
                  'SECRET_TOKEN_PATH': str(Path.home() / '.config/openbao/token')}
    client, _ = connect(connection)
    entity = client.lookup_entity_id()
    name = 'wallet-security/recovery'
    created = False
    try:
        stored, metadata = client.kv_get(entity, name)
    except SecretError as error:
        if str(error) != 'Secret not found.':
            raise
        generated = subprocess.run(['age-keygen'], capture_output=True, text=True, timeout=15, check=True)
        identity = generated.stdout
        public = subprocess.run(['age-keygen', '-y'], input=identity, capture_output=True,
                                text=True, timeout=15, check=True).stdout.strip()
        if 'AGE-SECRET-KEY-' not in identity or not re.fullmatch('age1[0-9a-z]+', public):
            raise SystemExit('Age recovery key generation did not validate')
        stored = {'contact_encryption_key': contact_key, 'age_identity': identity,
                  'age_recipient': public, 'workload_source_sha_at_enrollment': args.sha,
                  'application': 'cl8y-wallet-security'}
        # CAS=0 prevents overwriting any concurrent/existing custody record.
        client.request('POST', 'agent-secrets/data/' + entity + '/' + name,
                       {'options': {'cas': 0}, 'data': stored})
        created = True
    if stored.get('contact_encryption_key') != contact_key:
        raise SystemExit('Existing custody key differs; no overwrite or rotation attempted')
    original_nonce = secrets.token_bytes(12)
    fixture = b'owned-wallet-security-key-recovery-probe-v1'
    ciphertext = AESGCM(bytes.fromhex(contact_key)).encrypt(original_nonce, fixture, b'portal-custody-v1')
    del contact_key
    # A fresh client/read proves recovery from the authenticated backend.
    recovered_client, _ = connect(connection)
    if recovered_client.lookup_entity_id() != entity:
        raise SystemExit('Recovery identity changed unexpectedly')
    recovered, metadata = recovered_client.kv_get(entity, name)
    plaintext = AESGCM(bytes.fromhex(recovered['contact_encryption_key'])).decrypt(
        original_nonce, ciphertext, b'portal-custody-v1')
    if plaintext != fixture:
        raise SystemExit('Contact key recovery proof failed')
    encrypted = subprocess.run(['age', '-r', recovered['age_recipient']], input=fixture,
                               capture_output=True, timeout=15, check=True).stdout
    key_read, key_write = os.pipe()
    try:
        os.write(key_write, recovered['age_identity'].encode())
        os.close(key_write)
        key_write = -1
        decrypted = subprocess.run(['age', '-d', '-i', '/proc/self/fd/' + str(key_read)],
            input=encrypted, capture_output=True, pass_fds=(key_read,), timeout=15, check=True).stdout
    finally:
        os.close(key_read)
        if key_write >= 0:
            os.close(key_write)
    if decrypted != fixture:
        raise SystemExit('Age identity recovery proof failed')
    current = {item['key']: item for item in coolify('/envs') if not item.get('is_preview')}
    if current['CONTACT_ENCRYPTION_KEY']['value'] != recovered['contact_encryption_key']:
        raise SystemExit('Runtime canonical contact key changed during custody proof')
    receipt = {'workload_source_sha': args.sha, 'custody_backend': 'OpenBao existing identity-scoped private KV',
               'created': created, 'version': metadata.get('version'), 'contact_key_preserved': True,
               'fresh_backend_contact_decryption': True, 'fresh_backend_age_decryption': True,
               'plaintext_credential_files_written': False, 'credential_arguments_used': False,
               'workload_received_operator_or_recovery_credentials': False}
    private = {'kv_path': 'agent-secrets/data/' + entity + '/' + name,
               'version': metadata.get('version'), 'age_public_recipient': recovered['age_recipient']}
    Path('/tmp/wallet-security-ops/key-custody-private.json').write_text(json.dumps(private, indent=2))
    Path('/tmp/wallet-security-ops/key-custody-receipt.json').write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No exception body/child output: it may contain credentials or payloads.
        raise SystemExit('Key custody operation failed: ' + type(error).__name__) from None
