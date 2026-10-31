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
from backup_control import Api, Failure, NoRedirect, identifier, s3_client, s3_error_code, safe_main, validate_sealer, write_private, validate_lifecycle, require_no_bucket_policy
from export_observation import observe

MAX_CIPHER = 270 * 1024 * 1024


class UnknownTask(Failure):
    def __init__(self, record):
        super().__init__('owned_task_execution_outcome_unknown')
        self.record = record


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


def lease(client, entity, config, owner, release=False, renew=False):
    name = 'wallet-security/offhost-lease'
    current, metadata = optional_kv(client, entity, name)
    now = int(time.time())
    if current and current.get('volume') != config['resolved_sealed_volume']:
        raise Failure('lease_volume_binding_differs')
    if release:
        if current.get('owner') != owner: return
        if current.get('state') != 'clean' or json.loads(current.get('intents', '[]')):
            raise Failure('global_unresolved_backup_hold_cannot_release')
    elif renew:
        if current.get('owner') != owner or int(current.get('expires', '0')) <= now:
            raise Failure('backup_fencing_claim_lost_or_expired')
    elif int(current.get('expires', '0')) > now and current.get('owner') != owner:
        raise Failure('owned_volume_backup_busy')
    elif current and (current.get('state') != 'clean' or json.loads(current.get('intents', '[]'))):
        raise Failure('global_backup_reconciliation_required_before_failover')
    value = {'owner': owner, 'volume': config['resolved_sealed_volume'], 'expires': str(0 if release else now + 900),
             'state': current.get('state', 'clean') if renew else 'clean',
             'intents': current.get('intents', '[]') if renew else '[]'}
    client.request('POST', 'agent-secrets/data/' + entity + '/' + name,
                   {'options': {'cas': metadata['version']}, 'data': value})


def journal(client, entity, config, owner, action, record, persist):
    name = 'wallet-security/offhost-lease'
    current, metadata = optional_kv(client, entity, name)
    if (current.get('owner') != owner or current.get('volume') != config['resolved_sealed_volume']
        or int(current.get('expires', '0')) <= int(time.time())):
        raise Failure('global_backup_journal_fencing_claim_lost')
    intents = json.loads(current.get('intents', '[]'))
    key = record['intent_id']
    if action == 'begin':
        if any(item['intent_id'] == key for item in intents): raise Failure('duplicate_global_intent')
        intents.append(record)
    elif action == 'bind':
        found = [item for item in intents if item['intent_id'] == key]
        if len(found) != 1: raise Failure('global_intent_missing')
        found[0].update(record)
    elif action == 'resolved':
        if sum(item['intent_id'] == key for item in intents) != 1: raise Failure('global_intent_missing')
        intents = [item for item in intents if item['intent_id'] != key]
    else: raise Failure('invalid_global_journal_action')
    value = {**current, 'state': 'unresolved' if intents else 'clean',
             'intents': json.dumps(intents, sort_keys=True, separators=(',', ':'))}
    client.request('POST', 'agent-secrets/data/' + entity + '/' + name,
                   {'options': {'cas': metadata['version']}, 'data': value})
    config['global_unresolved'] = bool(intents)
    persist()


def new_claim(config):
    config.pop('lease_owner', None)
    owner = secrets.token_hex(16)
    config['last_run_claim'] = owner
    return owner


def wait_private_closed():
    deadline = time.monotonic() + 40
    while True:
        try:
            with socket.create_connection(('10.8.0.1', 18188), timeout=2): pass
        except ConnectionRefusedError:
            return
        except OSError:
            if time.monotonic() > deadline: raise Failure('private_export_cleanup_unproven') from None
        if time.monotonic() > deadline: raise Failure('private_export_listener_not_closed')
        time.sleep(1)


def task(api, service, name, command, timeout=210, intent=None):
    # A fresh disabled task is owned by this invocation, not a reused name with
    # historical executions that can masquerade as an unknown current dispatch.
    name = name + '-' + secrets.token_hex(8)
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
    baseline = api.call('GET', prefix + '/' + task_id + '/executions')
    if baseline:
        raise Failure('fresh_claim_task_has_prior_executions')
    started = dt.datetime.now(dt.timezone.utc)
    intent_id = 'task:' + task_id
    if intent:
        intent('begin', {'intent_id': intent_id, 'kind': 'task', 'service': service, 'task': task_id,
            'command': command, 'started_at': started.isoformat()})
    deadline = time.monotonic() + timeout
    executed = False
    try:
        # A response failure is not proof the queue rejected execution. Poll the
        # owned task before deciding its outcome or deleting its evidence.
        try:
            api.call('POST', prefix + '/' + task_id + '/execute')
        except Failure:
            pass
        while time.monotonic() < deadline:
            rows = api.call('GET', prefix + '/' + task_id + '/executions')
            for row in rows:
                created = row.get('created_at') or ''
                try: timestamp = dt.datetime.fromisoformat(created.replace('Z', '+00:00'))
                except ValueError: continue
                if timestamp < started - dt.timedelta(seconds=2): continue
                if row.get('status') == 'failed':
                    executed = True
                    raise Failure('owned_task_failed')
                if row.get('status') == 'success':
                    executed = True
                    return row.get('message') or ''
            time.sleep(1)
        raise UnknownTask({'service': service, 'task': task_id, 'name': name,
                           'command': command, 'started_at': started.isoformat()})
    except Failure:
        if not executed:
            raise UnknownTask({'service': service, 'task': task_id, 'name': name,
                               'command': command, 'started_at': started.isoformat()}) from None
        raise
    finally:
        if executed:
            api.call('DELETE', prefix + '/' + task_id)
            if intent: intent('resolved', {'intent_id': intent_id})


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
            wait_private_closed()
            # Keep the external cipher volume/networks; never run global cleanup.
            api.call('DELETE', '/services/' + exporter + '?delete_volumes=false&delete_connected_networks=false&docker_cleanup=false')
            try:
                api.call('GET', '/services/' + exporter)
            except Failure as error:
                if str(error) != 'control_plane_http_404': raise
            else:
                raise Failure('temporary_export_deletion_unconfirmed')
    # Model deletion does not establish daemon/listener cleanup by itself.
    wait_private_closed()
    config.pop('active_export', None)
    persist()


def fetch_cipher(api, config, record, persist, probe_only=False, fence=lambda: None, intent=None):
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
    intent_id = 'export:' + name
    if intent:
        intent('begin', {'intent_id': intent_id, 'kind': 'export', 'name': name, 'expires': str(expires),
            'compose': compose, 'context': config['resource_context'], 'server_uuid': config['server_uuid'],
            'destination_uuid': config['destination_uuid']})
    try:
        fence()
        created = api.call('POST', '/services', {'name': name, 'project_uuid': config['project_uuid'],
            'environment_uuid': config['environment_uuid'], 'server_uuid': config['server_uuid'],
            'destination_uuid': config['destination_uuid'], 'instant_deploy': False,
            'redact_all_env_values_in_logs': True, 'docker_compose_raw': base64.b64encode(raw.encode()).decode()})
        exporter = identifier(created['uuid']); config['active_export']['uuid'] = exporter; persist()
        if intent: intent('bind', {'intent_id': intent_id, 'resource_uuid': exporter})
        actual = api.call('GET', '/services/' + exporter)
        context_guard(actual, config, name, compose, exporter)
        api.call('PATCH', '/services/' + exporter + '/envs',
            {'key': 'EXPORT_TOKEN', 'value': token, 'is_literal': True, 'is_shown_once': True})
        actual = api.call('GET', '/services/' + exporter)
        context_guard(actual, config, name, compose, exporter)
        fence()
        api.call('POST', '/services/' + exporter + '/start')
        # A correct configuration/HEAD is not a daemon/private-listener proof.
        # The separate stopped operator observer reads only this new container.
        proof = observe(api, config, exporter, fence)
        config['last_private_runtime_observation'] = proof
        persist()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        endpoint = 'http://10.8.0.1:18188/cipher'
        deadline = time.monotonic() + 90
        while True:
            fence()
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
        fence()
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
        if intent: intent('resolved', {'intent_id': intent_id})
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
    require_no_bucket_policy(client, bucket)
    validate_lifecycle(client.get_bucket_lifecycle_configuration(Bucket=bucket))
    return bucket


def require_anonymous_object_denial(storage, bucket, key):
    import urllib.parse
    origin = urllib.parse.urlsplit(storage['endpoint'])
    encoded = urllib.parse.quote(key, safe='/')
    if storage.get('use_path_style_endpoint', True):
        url = storage['endpoint'].rstrip('/') + '/' + bucket + '/' + encoded
    else:
        url = origin.scheme + '://' + bucket + '.' + origin.netloc + '/' + encoded
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, method='HEAD'), timeout=10) as response:
            response.read(1024)
    except urllib.error.HTTPError as error:
        error.read(1024)
        if error.code in [403, 404]: return
        raise Failure('anonymous_object_privacy_unproven') from None
    raise Failure('offhost_object_anonymously_readable')


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
        if config.get('unknown_task'):
            raise Failure('owned_task_reconciliation_required_before_capture')
        def persist(): write_private(path, config)
        api = Api(); validate_sealer(api, config)
        if not config.get('daemon_binding_verified'): raise Failure('actual_cipher_volume_binding_unverified')
        for key in ['inspector_app_uuid', 'inspector_source_sha', 'inspector_name', 'export_image', 'export_source_sha']:
            if not config.get(key): raise Failure('reviewed_private_transport_plan_incomplete')
        health = json.load(urllib.request.urlopen('https://security.cl8y.com/healthz', timeout=10))
        if health.get('source_sha') != args.expected_source or health.get('migration') != args.expected_migration:
            raise Failure('workload_changed_or_migration_in_progress')
        client, entity = vault()
        # A copied config must never be an authorization to reuse another run's
        # active claim. Each invocation gets an independent fencing generation.
        owner = new_claim(config)
        persist(); lease(client, entity, config, owner)
        def fence(): lease(client, entity, config, owner, renew=True)
        def intent(action, record): journal(client, entity, config, owner, action, record, persist)
        paused = False
        try:
            cleanup_export(api, config, persist)
            fence()
            paused = True
            message = task(api, config['sealer_uuid'], 'wallet-security-offhost-pause', '/bin/bash /app/seal-backup.sh pause', intent=intent)
            record = ready_record(message)
            fence()
            ciphertext = fetch_cipher(api, config, record, persist, args.probe_only, fence, intent)
            if args.probe_only:
                print(json.dumps({'private_authenticated_head_probe': True, 'ciphertext_get_or_upload': False,
                    'temporary_export_stop_delete_confirmed': True, 'fresh_completed_pair_pause': True}))
                return
            # This independent metadata ledger authenticates producer provenance
            # against replacement by a party holding only S3 write credentials.
            ledger_name = 'wallet-security/backup-manifests/' + record['cipher_sha256']
            ledger = {'cipher_sha256': record['cipher_sha256'], 'dump': record['dump'],
                'observed_health_source_sha': args.expected_source, 'observed_health_migration': str(args.expected_migration),
                'producer_source_sha': config['sealer_source_sha']}
            existing, metadata = optional_kv(client, entity, ledger_name)
            if existing and existing != ledger: raise Failure('trusted_cipher_ledger_differs')
            if not existing:
                client.request('POST', 'agent-secrets/data/' + entity + '/' + ledger_name,
                    {'options': {'cas': 0}, 'data': ledger})
            fence()
            # Resume producer only after the full immutable ciphertext was
            # captured+hashed and the temporary reader was removed.
            task(api, config['sealer_uuid'], 'wallet-security-offhost-resume', '/bin/bash /app/seal-backup.sh resume', 30, intent)
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
                fence()
                ready_record('sealed_backup_ready dump=' + record['dump'] + ' cipher_sha256=' + record['cipher_sha256'])
                # Unique immutable content-addressed key; no reset of existing
                # object age or repeated stale-data uploads on a retry.
                s3.put_object(Bucket=bucket, Key=key, Body=ciphertext, ContentType='application/octet-stream',
                    Metadata={'cipher-sha256': record['cipher_sha256']}, IfNoneMatch='*')
            body = s3.get_object(Bucket=bucket, Key=key)['Body'].read(MAX_CIPHER + 1)
            if len(body) != len(ciphertext) or hashlib.sha256(body).hexdigest() != record['cipher_sha256']:
                raise Failure('offhost_readback_cipher_differs')
            require_anonymous_object_denial(storage, bucket, key)
            config['last_backup'] = {**record, 'object_key': key, 'observed_health_source_sha': args.expected_source,
                'observed_health_migration': args.expected_migration, 'cipher_bytes': len(body),
                'verified_at': dt.datetime.now(dt.timezone.utc).isoformat()}
            persist()
            if not args.quiet:
                print(json.dumps({'offhost_cipher_upload_and_readback': True, 'cipher_sha256': record['cipher_sha256'],
                    'cipher_bytes': len(body), 'observed_health_source_sha': args.expected_source, 'observed_health_migration': args.expected_migration,
                    'fresh_fenced_completed_pair': True, 'temporary_export_removed': True,
                    'private_keys_or_s3_credentials_in_workload': False, 'native_s3_helpers_invoked': False}))
        except UnknownTask as error:
            config['unknown_task'] = error.record
            persist()
            raise
        finally:
            # Cleanup uncertainty keeps the producer fenced and claim active.
            # The next owner must reconcile the exact old helper before resume.
            if not config.get('active_export') and not config.get('unknown_task') and not config.get('global_unresolved'):
                try:
                    if paused:
                        fence()
                        task(api, config['sealer_uuid'], 'wallet-security-offhost-resume', '/bin/bash /app/seal-backup.sh resume', 30, intent)
                except UnknownTask as error:
                    config['unknown_task'] = error.record
                    persist()
                    raise
                finally:
                    if not config.get('unknown_task') and not config.get('global_unresolved'):
                        lease(client, entity, config, owner, release=True)


if __name__ == '__main__': safe_main(main)
