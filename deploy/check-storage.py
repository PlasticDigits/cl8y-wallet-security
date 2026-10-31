#!/usr/bin/env python3
"""Verify the exact release image against disposable private PostgreSQL.

Uses the real SQLx migrator and exact image grants, verifies checksums against
Git objects, then tests denials and restores an archive into a scratch database.
All generated credentials remain in memory/environment; no ports are published.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--migration', type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.sha):
        parser.error('exact source SHA required')
    prefix = 'wallet-security-storage-' + secrets.token_hex(4)
    network, database, backups = prefix + '-net', prefix + '-pg', prefix + '-backups'
    env = {**os.environ, 'POSTGRES_PASSWORD': secrets.token_hex(32), 'POSTGRES_DB': 'wallet_security',
           'CONTACT_ENCRYPTION_KEY': secrets.token_hex(32), 'PUBLIC_ORIGIN': 'https://sandbox.invalid',
           'SOURCE_SHA': args.sha, 'BACKUP_ONCE': 'true'}
    for key in ('DB_MIGRATOR_PASSWORD', 'DB_API_PASSWORD', 'DB_WORKER_PASSWORD', 'DB_BACKUP_PASSWORD'):
        env[key] = secrets.token_hex(32)

    def run(command, text=None, check=True, timeout=150):
        result = subprocess.run(command, input=text, capture_output=True, text=True, env=env, timeout=timeout)
        if check and result.returncode:
            # Deliberately avoid printing raw stderr or an environment/command expansion.
            categories = [word for word in ('permission denied', 'does not exist', 'Connection refused',
                          'could not translate host name', 'password authentication failed') if word in result.stderr]
            raise SystemExit(json.dumps({'storage_check_failed': command[:2], 'categories': categories,
                                         'exit_code': result.returncode}))
        return result

    def sql(statement, role='postgres', check=True):
        return run(['docker', 'exec', '-i', database, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                    '-U', role, '-d', 'wallet_security'], statement, check=check)

    def image_job(mode, url_role, script=None, volume=False):
        password = env['POSTGRES_PASSWORD'] if url_role == 'postgres' else env['DB_' + url_role.upper() + '_PASSWORD']
        login = 'postgres' if url_role == 'postgres' else 'security_' + url_role
        env['DATABASE_URL'] = 'postgresql://' + login + ':' + password + '@postgres:5432/wallet_security'
        env['PROCESS_MODE'] = mode
        env['RUN_MIGRATIONS'] = 'true' if mode == 'migrate' else 'false'
        command = ['docker', 'run', '--rm', '--network', network, '--read-only', '--tmpfs', '/tmp:size=16m,mode=1777',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true']
        for key in ('DATABASE_URL', 'CONTACT_ENCRYPTION_KEY', 'PUBLIC_ORIGIN', 'SOURCE_SHA',
                    'PROCESS_MODE', 'RUN_MIGRATIONS', 'BACKUP_ONCE'):
            command += ['-e', key]
        if volume:
            command += ['--user', 'postgres', '-v', backups + ':/backups' + (':ro' if mode == 'restore' else '')]
        if script:
            command += ['--entrypoint', '/bin/bash', args.image, '/app/deploy/' + script]
        else:
            command += [args.image]
        return run(command)

    revision = run(['docker', 'image', 'inspect', '--format', '{{index .Config.Labels "org.opencontainers.image.revision"}}', args.image]).stdout.strip()
    if revision != args.sha:
        raise SystemExit('Image revision label differs from requested source SHA')
    user = run(['docker', 'image', 'inspect', '--format', '{{.Config.User}}', args.image]).stdout.strip()
    if user != '10001:10001':
        raise SystemExit('Image runtime user is not 10001:10001')
    # Use exact source bytes, not the mutable working tree or fabricated history.
    files = run(['git', 'ls-tree', '-r', '--name-only', args.sha, 'api/migrations']).stdout.splitlines()
    expected = {}
    for filename in files:
        if filename.endswith('.sql'):
            version = int(Path(filename).name.split('_')[0])
            body = subprocess.run(['git', 'show', args.sha + ':' + filename], capture_output=True, check=True, timeout=20).stdout
            expected[version] = hashlib.sha384(body).hexdigest()
    if not expected or max(expected) != args.migration:
        raise SystemExit('Expected migration version differs from pinned Git migration set')
    bootstrap = tempfile.TemporaryDirectory(prefix=prefix + '-')
    init_script = Path(bootstrap.name) / 'postgres-init.sh'
    init_script.write_bytes(subprocess.run(['git', 'show', args.sha + ':deploy/postgres-init.sh'],
                           capture_output=True, check=True, timeout=20).stdout)
    init_script.chmod(0o644)  # Public source only; readable by container uid 999.
    created_network = created_volume = started_database = False
    try:
        run(['docker', 'network', 'create', '--internal', network]); created_network = True
        run(['docker', 'volume', 'create', backups]); created_volume = True
        # Copy-on-create preserves /backups ownership from the exact release image.
        run(['docker', 'run', '--rm', '--network', 'none', '--user', 'postgres', '-v', backups + ':/backups',
             '--entrypoint', '/usr/bin/test', args.image, '-w', '/backups'])
        command = ['docker', 'run', '-d', '--name', database, '--network', network, '--network-alias', 'postgres',
                   '--user', 'postgres', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                   '--tmpfs', '/var/lib/postgresql/data:uid=999,gid=999',
                   '-v', str(init_script) + ':/docker-entrypoint-initdb.d/10-roles.sh:ro']
        for key in ('POSTGRES_PASSWORD', 'POSTGRES_DB', 'DB_MIGRATOR_PASSWORD', 'DB_API_PASSWORD', 'DB_WORKER_PASSWORD', 'DB_BACKUP_PASSWORD'):
            command += ['-e', key]
        command += ['postgres:17.6-bookworm@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3']
        run(command); started_database = True
        for _ in range(40):
            # TCP ensures init scripts have completed and the final server is running.
            if run(['docker', 'exec', database, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], check=False).returncode == 0:
                break
            time.sleep(.5)
        else:
            raise SystemExit('Disposable PostgreSQL did not become ready within 20 seconds')
        image_job('migrate', 'migrator')
        rows = sql("SELECT version,success,encode(checksum,'hex') FROM _sqlx_migrations ORDER BY version").stdout.splitlines()
        actual = {}
        for row in rows:
            version, success, checksum = row.split('|')
            if success != 't':
                raise SystemExit('Unsuccessful SQLx migration')
            actual[int(version)] = checksum
        if actual != expected:
            raise SystemExit('Actual SQLx history/checksums differ from the exact pinned source')
        image_job('grants', 'migrator', 'grants.sh')
        checks = {'exact_real_migration_history': True, 'image_nonroot': True}
        for role in ('security_api', 'security_worker'):
            for label, statement in (
                ('ddl', 'BEGIN; CREATE TABLE public.deployment_denial_probe(id int); ROLLBACK;'),
                ('history_write', 'BEGIN; DELETE FROM _sqlx_migrations WHERE false; ROLLBACK;')):
                result = sql(statement, role=role, check=False)
                checks[role + '_' + label + '_denied'] = result.returncode != 0 and 'permission denied' in result.stderr
        for label, statement in (
            ('session_insert', "BEGIN; INSERT INTO sessions(token_hash,profile_id,csrf_token,expires_at) SELECT 'sandbox',id,'sandbox',now() FROM profiles WHERE false; ROLLBACK;"),
            ('session_update', "BEGIN; UPDATE sessions SET csrf_token='sandbox' WHERE false; ROLLBACK;")):
            result = sql(statement, role='security_worker', check=False)
            checks['worker_' + label + '_denied'] = result.returncode != 0 and 'permission denied' in result.stderr
        sql("BEGIN; INSERT INTO profiles(id,anchor_wallet) VALUES('00000000-0000-0000-0000-000000000001','owned-unfunded-sandbox'); ROLLBACK;", role='security_api')
        checks['api_dml'] = True
        result = sql('BEGIN; DELETE FROM profiles WHERE false; ROLLBACK;', role='security_backup', check=False)
        checks['backup_read_only'] = result.returncode != 0 and 'permission denied' in result.stderr
        image_job('backup', 'backup', 'backup.sh', volume=True)
        restored = image_job('restore', 'postgres', 'restore-drill.sh', volume=True)
        checks['backup_restore'] = bool(re.fullmatch(r'restore_drill_pass migration=' + str(args.migration) + r' public_tables=\d+ archive_sha256=[0-9a-f]{64}\n?', restored.stdout))
        print(json.dumps({'source_sha': args.sha, 'migration': args.migration, 'migration_count': len(actual), 'checks': checks}, sort_keys=True))
        if checks['backup_restore']:
            print(restored.stdout.strip())
        if not all(checks.values()):
            raise SystemExit('One or more exact-image storage assertions failed')
    finally:
        if started_database:
            run(['docker', 'rm', '-f', database], check=False)
        if created_volume:
            run(['docker', 'volume', 'rm', backups], check=False)
        if created_network:
            run(['docker', 'network', 'rm', network], check=False)
        bootstrap.cleanup()


if __name__ == '__main__':
    main()
