#!/usr/bin/env python3
"""Proposed BB script automation. Not installed or activated by this source file."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ARTIFACTS = {'release_source': '4c5995b26f84c35af55e0bc7cf6cc5cc0b027706', 'release_path': '/home/answorld/.local/share/wallet-security-ops/releases/4c5995b26f84c35af55e0bc7cf6cc5cc0b027706', 'sha256': {'deploy/backup-capture.py': '8e8fe12dccebc58f1fe452af4b5b57ff1124b741f3a0692b599db0482f973328', 'deploy/backup_control.py': '5322243ad2c37037b20582b715214143e44cd839d3f4a1e5f15bff5052daf7db', 'deploy/export_observation.py': '19856a4feae0a2dfaad7d993636c54bf3af4cd631f1c163bffd3ff75ed522c9c', 'deploy/cipher-export/compose.yml': 'e7f523a5d63ac44d5880e0a0cdf833833a6f85c217bc775e2837da090f7cc173', 'deploy/backup-inspector/compose.yml': 'ae802b33d87df2ac916681bcdc63ca4bfc018243094a38aaccd74cdde704455c'}, 'metadata_helper_path': '/home/answorld/.local/share/wallet-security-ops/proposals/persist-offhost-config-7e92fc07ab4cb2fc92b19760488ca3da740030287c170e0cad07ef9c023da3f9.py', 'metadata_helper_sha256': '7e92fc07ab4cb2fc92b19760488ca3da740030287c170e0cad07ef9c023da3f9'}
OPS = Path('/home/answorld/.local/share/wallet-security-ops')
PYTHON = OPS / 'venv/bin/python'
CONFIG = OPS / 'offhost-config.json'
SOURCE = '4fbe03977337925f6185b393a8aa39437095b097'
OWNER_THREAD = 'thr_4rw76j9ker'
phase = 'context'


def run(command, timeout, env=None):
    value = subprocess.run(command, capture_output=True, timeout=timeout, env=env)
    if value.returncode:
        raise RuntimeError('closed_operation_failure')
    return value


def main():
    global phase
    os.umask(0o077)
    if not os.environ.get('BB_AUTOMATION_ID') or not os.environ.get('BB_CLI'):
        raise RuntimeError('native_automation_context_required')
    phase = 'fixed_source'
    release = Path(ARTIFACTS['release_path'])
    for name, expected in ARTIFACTS['sha256'].items():
        if hashlib.sha256((release / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError('controller_source_changed')
    helper = Path(ARTIFACTS['metadata_helper_path'])
    if hashlib.sha256(helper.read_bytes()).hexdigest() != ARTIFACTS['metadata_helper_sha256']:
        raise RuntimeError('metadata_source_changed')
    phase = 'private_routes'
    for destination in ['10.8.0.1', '10.10.0.4']:
        routes = json.loads(run(['ip', '-j', 'route', 'get', destination], 5).stdout)
        if (len(routes) != 1 or routes[0].get('dev') != 'wg0'
                or routes[0].get('prefsrc') != '10.8.0.2'):
            raise RuntimeError('private_route_unavailable')
    phase = 'certificate_login'
    env = {k: v for k, v in os.environ.items() if not k.startswith(('BAO_', 'VAULT_'))}
    cert = Path('/home/answorld/.config/openbao')
    env.update(BAO_ADDR='https://10.10.0.4:8200', BAO_CACERT=str(cert / 'ca.crt'),
        BAO_CLIENT_CERT=str(cert / 'client.crt'), BAO_CLIENT_KEY=str(cert / 'client.key'),
        BAO_TOKEN_PATH=str(cert / 'token'), BAO_DISABLE_REDIRECTS='true',
        BAO_CLIENT_TIMEOUT='10s', BAO_MAX_RETRIES='0', BAO_FORMAT='json',
        NO_PROXY='10.10.0.4', no_proxy='10.10.0.4')
    run(['/home/answorld/.local/bin/bao', 'login', '-no-print', '-method=cert',
         '-path=workstation-cert', 'name=answorld-pop-os'], 30, env)
    phase = 'guarded_capture'
    run(['/home/answorld/.local/bin/bao-exec', '--only', 'COOLIFY_URL,COOLIFY_WIRE_TOKEN',
         '--', str(PYTHON), str(release / 'deploy/backup-capture.py'), '--config', str(CONFIG),
         '--expected-source', SOURCE, '--expected-migration', '6', '--quiet'], 330)
    phase = 'durable_state'
    state = json.loads(run([str(PYTHON), str(helper), '--controller-release', str(release),
                           '--config', str(CONFIG)], 90).stdout)
    if not isinstance(state.get('durable_readback_version'), int):
        raise RuntimeError('durable_state_readback_invalid')
    latest = json.loads(CONFIG.read_text())['last_backup']
    print(json.dumps({'offhost_backup_verified': True, 'dump_utc': latest['stamp'],
        'cipher_sha256': latest['cipher_sha256'],
        'durable_readback_version': state['durable_readback_version']}))


def failed():
    # Only this backup's failure is routed to its existing agent owner; no logs.
    marker = OPS / 'daily-last-owner-notice'
    notified = False
    cli = os.environ.get('BB_CLI')
    if cli and (not marker.exists() or time.time() - marker.stat().st_mtime > 21600):
        message = ('Wallet-security offhost automation failed at closed phase ' + phase +
            '. Reconcile the exact private journal and owned resources; preserve unknown holds. '
            'No human setup or automatic stale-claim takeover is authorized.')
        try:
            value = subprocess.run([cli, 'thread', 'tell', OWNER_THREAD, '--message-file', '-'],
                input=message.encode(), capture_output=True, timeout=20)
            if value.returncode == 0:
                marker.touch(mode=0o600); notified = True
        except Exception:
            pass
    print(json.dumps({'offhost_daily_failed': True, 'phase': phase,
                      'existing_agent_owner_notified': notified}), file=sys.stderr)
    raise SystemExit(1)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        failed()
