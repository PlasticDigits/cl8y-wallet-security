#!/usr/bin/env python3
"""Persist only clean owned backup metadata; no recovery/S3 keys are loaded."""
import argparse
import fcntl
import importlib.util
import json
from pathlib import Path
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller-release', required=True)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    with Path(args.config).with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        persist(args)


def persist(args):
    deploy = Path(args.controller_release) / 'deploy'
    sys.path.insert(0, str(deploy))
    from backup_control import Failure
    spec = importlib.util.spec_from_file_location('capture', deploy / 'backup-capture.py')
    capture = importlib.util.module_from_spec(spec); spec.loader.exec_module(capture)
    cfg = json.loads(Path(args.config).read_text())
    if (not cfg.get('bucket_created_by_this_operator') or not cfg.get('bucket_owner_id')
            or not cfg.get('last_backup') or cfg.get('active_export')
            or cfg.get('unknown_task') or cfg.get('global_unresolved')):
        raise Failure('clean_owned_config_required')
    client, entity = capture.vault()
    lease, _ = client.kv_get(entity, 'wallet-security/offhost-lease')
    if (lease.get('owner') != cfg.get('last_run_claim')
            or lease.get('volume') != cfg['resolved_sealed_volume']
            or lease.get('state') != 'clean' or json.loads(lease.get('intents', '[]'))
            or int(lease.get('expires', '0')) > int(time.time())):
        raise Failure('released_clean_journal_required')
    name = 'wallet-security/offhost-config'
    existing, metadata = client.kv_get(entity, name)
    prior = json.loads(existing['config_json'])
    for key in ['portal_app_uuid', 'sealer_uuid', 'bucket_name', 'bucket_owner_id',
                'resolved_sealed_volume', 'server_uuid', 'destination_uuid']:
        if prior.get(key) != cfg.get(key):
            raise Failure('durable_owned_identity_changed')
    if prior.get('active_export') or prior.get('unknown_task') or prior.get('global_unresolved'):
        raise Failure('durable_hold_requires_reconciliation')
    last = cfg['last_backup']
    history = cfg.setdefault('backup_history', {})
    if last['cipher_sha256'] in history:
        if history[last['cipher_sha256']]['object_key'] != last['object_key']:
            raise Failure('prior_history_object_binding_differs')
    else:
        history[last['cipher_sha256']] = last
    value = {'config_json': json.dumps(cfg, sort_keys=True, separators=(',', ':'))}
    client.request('POST', 'agent-secrets/data/' + entity + '/' + name,
                   {'options': {'cas': metadata['version']}, 'data': value})
    actual, metadata = client.kv_get(entity, name)
    if actual != value:
        raise Failure('durable_config_readback_differs')
    from backup_control import write_private
    write_private(args.config, cfg)
    print(json.dumps({'durable_readback_version': metadata['version']}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('offhost_daily_failed phase=durable_config') from None
