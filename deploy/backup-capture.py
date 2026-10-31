#!/usr/bin/env python3
"""Operator-only fenced ciphertext capture; never loads private recovery keys.

Credentials: brokered Coolify/S3 only in operator memory; a separate temporary
workload receives only a short-lived read capability through protected ENV.
"""
import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
import yaml
from backup_control import Api, Failure, NoRedirect, identifier, s3_client, s3_error_code, safe_main, validate_sealer, write_private

MAX_CIPHER = 270 * 1024 * 1024


def vault():
    sys.path.insert(0, '/home/answorld/openbao-ops')
    from agent_secret.client import connect
    client, _ = connect({**os.environ, 'SECRET_FORCE_DIRECT': '1', 'SECRET_ADDR': 'https://10.10.0.4:8200',
        'SECRET_CACERT': str(Path.home() / '.config/openbao/ca.crt'),
        'SECRET_TOKEN_PATH': str(Path.home() / '.config/openbao/token')})
    return client, client.lookup_entity_id()


def optional_kv(client, entity, name):
    from agent_secret.client import SecretError
    try: return client.kv_get(entity, name)
    except SecretError as error:
        if str(error) == 'Secret not found.': return {}, {'version': 0}
        raise


def lease(client, entity, config, owner, release=False):
    name = 'wallet-security/offhost-lease'
    current, metadata = optional_kv(client, entity, name)
    now = int(time.time())
    if current and current.get('volume') != config['resolved_sealed_volume']:
        raise Failure('lease_volume_binding_differs')
    if release:
        if current.get('owner') != owner: return
    elif int(current.get('expires', '0')) > now and current.get('owner') != owner:
        raise Failure('owned_volume_backup_busy')
    value = {'owner': owner, 'volume': config['resolved_sealed_volume'], 'expires': str(0 if release else now + 900)}
    client.request('POST', 'agent-secrets/data/' + entity + '/' + name,
                   {'options': {'cas': metadata['version']}, 'data': value})


def task(api, service, name, command, timeout=210):
    prefix = '/services/' + identifier(service) + '/scheduled-tasks'
    found = [item for item in api.call('GET', prefix) if item.get('name') == name]
    if len(found) > 1: raise Failure('ambiguous_owned_task')
    if found:
        item = found[0]
        if item.get('command') != command or item.get('enabled'): raise Failure('owned_task_drift')
    else:
        item = api.call('POST', prefix, {'name': name, 'command': command,
              'frequency': '0 0 1 1 *', 'timeout': timeout, 'enabled': False})
    task_id = identifier(item['uuid'])
    started = dt.datetime.now(dt.timezone.utc)
    api.call('POST', prefix + '/' + task_id + '/execute')
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            rows = api.call('GET', prefix + '/' + task_id + '/executions')
            for row in rows:
                created = row.get('created_at') or ''
                try: timestamp = dt.datetime.fromisoformat(created.replace('Z', '+00:00'))
                except ValueError: continue
                if timestamp < started - dt.timedelta(seconds=2): continue
                if row.get('status') == 'failed': raise Failure('owned_task_failed')
                if row.get('status') == 'success': return row.get('message') or ''
            time.sleep(1)
        raise Failure('owned_task_deadline')
    finally:
        api.call('DELETE', prefix + '/' + task_id)


def ready_record(message):
    records = []
    for line in message.splitlines():
        match = re.fullmatch(r'sealed_backup_ready dump=(wallet-security-(\d{8}T\d{6}Z)\.dump) cipher_sha256=([0-9a-f]{64})', line)
        if match: records.append(match)
    if not records: raise Failure('completed_pair_record_absent')
    match = records[-1]
    timestamp = dt.datetime.strptime(match[2], '%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)
    age = (dt.datetime.now(dt.timezone.utc) - timestamp).total_seconds()
    if age < -60 or age > 90000: raise Failure('source_dump_stale')
    return {'dump': match[1], 'stamp': match[2], 'cipher_sha256': match[3]}


def context_guard(resource, config, expected_name, compose, expected_uuid):
    destination = resource.get('destination') or {}
    if (resource.get('uuid') != expected_uuid or resource.get('name') != expected_name
        or any(resource.get(key) != value for key, value in config['resource_context'].items())
        or destination.get('uuid') != config['destination_uuid']
        or (destination.get('server') or {}).get('uuid') != config['server_uuid']
        or yaml.safe_load(resource.get('docker_compose_raw') or '') != compose):
        raise Failure('temporary_export_resource_drift')


def cleanup_export(api, config, persist):
    active = config.get('active_export')
    if not active: return
    exporter = active.get('uuid')
    if not exporter:
        found = [item for item in api.call('GET', '/services') if item.get('name') == active['name']]
        if len(found) > 1: raise Failure('ambiguous_export_create_outcome')
        if found: exporter = identifier(found[0]['uuid'])
    if exporter:
        try: resource = api.call('GET', '/services/' + identifier(exporter))
        except Failure as error:
            if str(error) != 'control_plane_http_404': raise
        else:
            context_guard(resource, config, active['name'], active['compose'], exporter)
            api.call('POST', '/services/' + exporter + '/stop')
            deadline = time.monotonic() + 40
            while True:
                try:
                    with socket.create_connection(('10.8.0.1', 18188), timeout=2): pass
                except ConnectionRefusedError:
                    break
                except OSError:
                    if time.monotonic() > deadline: raise Failure('private_export_cleanup_unproven') from None
                if time.monotonic() > deadline: raise Failure('private_export_listener_not_closed')
                time.sleep(1)
            # Keep the external cipher volume/networks; never run global cleanup.
            api.call('DELETE', '/services/' + exporter + '?delete_volumes=false&delete_connected_networks=false&docker_cleanup=false')
            try:
                api.call('GET', '/services/' + exporter)
            except Failure as error:
                if str(error) != 'control_plane_http_404': raise
            else:
                raise Failure('temporary_export_deletion_unconfirmed')
    config.pop('active_export', None)
    persist()


def fetch_cipher(api, config, record, persist, probe_only=False):
    # Never take over an occupied private listener belonging to another role.
    try:
        with socket.create_connection(('10.8.0.1', 18188), timeout=2): pass
    except ConnectionRefusedError:
        pass
    except OSError:
        raise Failure('private_interface_or_listener_state_unproven') from None
    else:
        raise Failure('private_export_port_already_in_use')
    token = secrets.token_hex(32)
    expires = int(time.time()) + 600
    name = 'wallet-security-cipher-export-' + secrets.token_hex(8)
    raw = Path(__file__).with_name('cipher-export').joinpath('compose.yml').read_text()
    values = {'CIPHER_EXPORT_IMAGE': config['export_image'], 'EXPECTED_CIPHER_SHA256': record['cipher_sha256'],
              'EXPORT_FILENAME': record['dump'] + '.age', 'EXPORT_EXPIRES_UNIX': str(expires),
              'SEALED_BACKUP_VOLUME': config['resolved_sealed_volume']}
    for key, value in values.items(): raw = raw.replace('${' + key + ':?}', value)
    # EXPORT_TOKEN remains a literal protected runtime variable reference.
    compose = yaml.safe_load(raw)
    config['active_export'] = {'name': name, 'expires': expires, 'compose': compose}
    persist()
    try:
        created = api.call('POST', '/services', {'name': name, 'project_uuid': config['project_uuid'],
            'environment_uuid': config['environment_uuid'], 'server_uuid': config['server_uuid'],
            'destination_uuid': config['destination_uuid'], 'instant_deploy': False,
            'redact_all_env_values_in_logs': True, 'docker_compose_raw': base64.b64encode(raw.encode()).decode()})
        exporter = identifier(created['uuid']); config['active_export']['uuid'] = exporter; persist()
        actual = api.call('GET', '/services/' + exporter)
        context_guard(actual, config, name, compose, exporter)
        api.call('PATCH', '/services/' + exporter + '/envs',
            {'key': 'EXPORT_TOKEN', 'value': token, 'is_literal': True, 'is_shown_once': True})
        actual = api.call('GET', '/services/' + exporter)
        context_guard(actual, config, name, compose, exporter)
        api.call('POST', '/services/' + exporter + '/start')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        endpoint = 'http://10.8.0.1:18188/cipher'
        deadline = time.monotonic() + 90
        while True:
            try:
                request = urllib.request.Request(endpoint, method='HEAD', headers={'Authorization': 'Bearer ' + token})
                with opener.open(request, timeout=5) as response:
                    length = int(response.headers.get('Content-Length', '0'))
                    if response.status != 200 or length <= 0 or length > MAX_CIPHER: raise Failure('private_export_invalid_length')
                    break
            except (urllib.error.URLError, OSError):
                if time.monotonic() > deadline: raise Failure('private_export_not_ready') from None
                time.sleep(1)
        if probe_only:
            return None
        request = urllib.request.Request(endpoint, headers={'Authorization': 'Bearer ' + token})
        with opener.open(request, timeout=30) as response:
            ciphertext = response.read(MAX_CIPHER + 1)
        if len(ciphertext) != length or len(ciphertext) > MAX_CIPHER or not ciphertext.startswith(b'age-encryption.org/v1\n'):
            raise Failure('private_export_incomplete')
        if hashlib.sha256(ciphertext).hexdigest() != record['cipher_sha256']:
            raise Failure('whole_cipher_hash_differs_before_upload')
        return ciphertext
    finally:
        cleanup_export(api, config, persist)
        del token


def check_bucket(client, config):
    bucket = 'cl8y-wallet-security-' + identifier(config['portal_app_uuid'])[:12] + '-encrypted'
    if config.get('bucket_name') != bucket or not config.get('bucket_created_by_this_operator'):
        raise Failure('offhost_bucket_ownership_unproven')
    acl = client.get_bucket_acl(Bucket=bucket)
    if acl.get('Owner', {}).get('ID') != config['bucket_owner_id']:
        raise Failure('offhost_bucket_owner_changed')
    if any(grant.get('Grantee', {}).get('Type') != 'CanonicalUser'
           or grant.get('Grantee', {}).get('ID') != config['bucket_owner_id'] for grant in acl.get('Grants', [])):
        raise Failure('offhost_bucket_not_private')
    if client.get_bucket_versioning(Bucket=bucket).get('Status'):
        raise Failure('offhost_bucket_versioned')
    rules = client.get_bucket_lifecycle_configuration(Bucket=bucket).get('Rules', [])
    if (len(rules) != 1 or rules[0].get('Expiration', {}).get('Days') != 4
        or rules[0].get('Status') != 'Enabled' or rules[0].get('AbortIncompleteMultipartUpload', {}).get('DaysAfterInitiation') != 1
        or rules[0].get('ID') != 'wallet-security-four-day-expiry'
        or rules[0].get('Prefix', (rules[0].get('Filter') or {}).get('Prefix', '')) != ''):
        raise Failure('offhost_lifecycle_drift')
    return bucket


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--expected-migration', type=int, required=True)
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--probe-only', action='store_true', help='Authenticated private HEAD only, no ciphertext GET/S3 operations')
    args = parser.parse_args()
    path = Path(args.config)
    with path.with_suffix('.lock').open('a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise Failure('local_backup_actor_busy') from None
        config = json.loads(path.read_text())
        def persist(): write_private(path, config)
        api = Api(); validate_sealer(api, config)
        if not config.get('daemon_binding_verified'): raise Failure('actual_cipher_volume_binding_unverified')
        health = json.load(urllib.request.urlopen('https://security.cl8y.com/healthz', timeout=10))
        if health.get('source_sha') != args.expected_source or health.get('migration') != args.expected_migration:
            raise Failure('workload_changed_or_migration_in_progress')
        client, entity = vault(); owner = config.get('lease_owner') or secrets.token_hex(16)
        config['lease_owner'] = owner; persist(); lease(client, entity, config, owner)
        paused = False
        try:
            cleanup_export(api, config, persist)
            paused = True
            message = task(api, config['sealer_uuid'], 'wallet-security-offhost-pause', '/bin/bash /app/seal-backup.sh pause')
            record = ready_record(message)
            ciphertext = fetch_cipher(api, config, record, persist, args.probe_only)
            if args.probe_only:
                print(json.dumps({'private_authenticated_head_probe': True, 'ciphertext_get_or_upload': False,
                    'temporary_export_stop_delete_confirmed': True, 'fresh_completed_pair_pause': True}))
                return
            # This independent metadata ledger authenticates producer provenance
            # against replacement by a party holding only S3 write credentials.
            ledger_name = 'wallet-security/backup-manifests/' + record['cipher_sha256']
            ledger = {'cipher_sha256': record['cipher_sha256'], 'dump': record['dump'],
                'workload_source_sha': args.expected_source, 'migration': str(args.expected_migration),
                'producer_source_sha': config['sealer_source_sha']}
            existing, metadata = optional_kv(client, entity, ledger_name)
            if existing and existing != ledger: raise Failure('trusted_cipher_ledger_differs')
            if not existing:
                client.request('POST', 'agent-secrets/data/' + entity + '/' + ledger_name,
                    {'options': {'cas': 0}, 'data': ledger})
            # Resume producer only after the full immutable ciphertext was
            # captured+hashed and the temporary reader was removed.
            task(api, config['sealer_uuid'], 'wallet-security-offhost-resume', '/bin/bash /app/seal-backup.sh resume', 30)
            paused = False
            storage = api.call('GET', '/s3-storages/' + identifier(config['s3_source_uuid']))
            s3 = s3_client(storage); bucket = check_bucket(s3, config)
            key = 'backups/' + record['dump'] + '.' + record['cipher_sha256'] + '.age'
            present = False
            try:
                head = s3.head_object(Bucket=bucket, Key=key)
                present = True
            except Exception as error:
                if s3_error_code(error) not in {'404', 'NoSuchKey'}: raise
            if not present:
                ready_record('sealed_backup_ready dump=' + record['dump'] + ' cipher_sha256=' + record['cipher_sha256'])
                # Unique immutable content-addressed key; no reset of existing
                # object age or repeated stale-data uploads on a retry.
                s3.put_object(Bucket=bucket, Key=key, Body=ciphertext, ContentType='application/octet-stream',
                    Metadata={'cipher-sha256': record['cipher_sha256']}, IfNoneMatch='*')
            body = s3.get_object(Bucket=bucket, Key=key)['Body'].read(MAX_CIPHER + 1)
            if len(body) != len(ciphertext) or hashlib.sha256(body).hexdigest() != record['cipher_sha256']:
                raise Failure('offhost_readback_cipher_differs')
            config['last_backup'] = {**record, 'object_key': key, 'source_sha': args.expected_source,
                'migration': args.expected_migration, 'cipher_bytes': len(body),
                'verified_at': dt.datetime.now(dt.timezone.utc).isoformat()}
            persist()
            if not args.quiet:
                print(json.dumps({'offhost_cipher_upload_and_readback': True, 'cipher_sha256': record['cipher_sha256'],
                    'cipher_bytes': len(body), 'source_sha': args.expected_source, 'migration': args.expected_migration,
                    'fresh_fenced_completed_pair': True, 'temporary_export_removed': True,
                    'private_keys_or_s3_credentials_in_workload': False, 'native_s3_helpers_invoked': False}))
        finally:
            try:
                if paused:
                    task(api, config['sealer_uuid'], 'wallet-security-offhost-resume', '/bin/bash /app/seal-backup.sh resume', 30)
            finally:
                lease(client, entity, config, owner, release=True)


if __name__ == '__main__': safe_main(main)
