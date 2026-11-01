#!/usr/bin/env python3
"""Persist only clean owned backup metadata; no recovery/S3 keys are loaded."""
import argparse
import fcntl
import importlib.util
import json
from pathlib import Path
import sys
import time


def preserve_history(prior, current):
    history = {}
    immutable = ['cipher_sha256', 'object_key', 'dump', 'stamp', 'cipher_bytes',
                 'observed_health_source_sha', 'observed_health_migration']
    for state in [prior, current]:
        entries = list(state.get('backup_history', {}).items())
        last = state.get('last_backup')
        if last:
            entries.append((last['cipher_sha256'], last))
        for digest, entry in entries:
            if not isinstance(entry, dict) or entry.get('cipher_sha256') != digest:
                raise ValueError('history_identity_invalid')
            merged = history.setdefault(digest, {})
            for key in immutable:
                if key in merged and key in entry and merged[key] != entry[key]:
                    raise ValueError('history_immutable_binding_conflict')
            for key, value in entry.items():
                merged.setdefault(key, value)
    prior_last = prior.get('last_backup')
    if prior_last and prior_last['stamp'] > current['last_backup']['stamp']:
        current['last_backup'] = prior_last
    current['backup_history'] = history


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
    preserve_history(prior, cfg)
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
