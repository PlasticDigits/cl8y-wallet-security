#!/usr/bin/env python3
"""Recover only into a disposable offline DB, using fresh scoped vault reads.

Never promotes a database, starts API/delivery/chain workers, or mutates live
sessions/data. Private age identity is supplied through an inherited pipe only.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from backup_control import Api, Failure, identifier, s3_client, safe_main


def main(owned_trial_session_counter=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--min-smtp-sent-with-first-attempt', type=int, default=0)
    args = parser.parse_args()
    if args.min_smtp_sent_with_first_attempt < 0:
        raise Failure('invalid_minimum_smtp_evidence_count')
    spec = importlib.util.spec_from_file_location('capture', Path(__file__).with_name('backup-capture.py'))
    capture = importlib.util.module_from_spec(spec); spec.loader.exec_module(capture)
    cfg = json.loads(Path(args.config).read_text()); last = cfg.get('last_backup')
    if not last: raise Failure('verified_offhost_object_absent')
    expected = last['cipher_sha256']; key = 'backups/' + last['dump'] + '.' + expected + '.age'
    if key != last['object_key']: raise Failure('own_object_binding_differs')
    api = Api(); storage = api.call('GET', '/s3-storages/' + identifier(cfg['s3_source_uuid']))
    s3 = s3_client(storage); bucket = capture.check_bucket(s3, cfg)
    result = s3.get_object(Bucket=bucket, Key=key)
    if result.get('ContentLength', 0) > capture.MAX_CIPHER: raise Failure('offhost_object_too_large')
    cipher = result['Body'].read(capture.MAX_CIPHER + 1)
    if len(cipher) > capture.MAX_CIPHER or hashlib.sha256(cipher).hexdigest() != expected:
        raise Failure('offhost_cipher_hash_mismatch')
    client, entity = capture.vault()
    ledger, _ = client.kv_get(entity, 'wallet-security/backup-manifests/' + expected)
    if ledger.get('cipher_sha256') != expected or ledger.get('dump') != last['dump'] or ledger.get('observed_health_source_sha') != last['observed_health_source_sha']:
        raise Failure('independent_producer_ledger_differs')
    recovery, metadata = client.kv_get(entity, cfg['custody_name'])
    read, write = os.pipe()
    try:
        os.write(write, recovery['age_identity'].encode()); os.close(write); write = -1
        decrypted = subprocess.run(['age', '-d', '-i', '/proc/self/fd/' + str(read)], input=cipher,
            capture_output=True, pass_fds=(read,), timeout=90)
    finally:
        os.close(read)
        if write >= 0: os.close(write)
    if decrypted.returncode or not decrypted.stdout.startswith(b'PGDMP'):
        raise Failure('fresh_vault_age_recovery_failed')
    dump = decrypted.stdout
    # Isolate the restored schema/data completely from delivery and chain paths.
    name = 'wallet-security-offhost-restore-' + secrets.token_hex(4)
    env = {**os.environ, 'POSTGRES_PASSWORD': secrets.token_hex(32), 'POSTGRES_DB': 'wallet_restore'}

    def run(command, content=None, check=True, timeout=60):
        value = subprocess.run(command, input=content, capture_output=True, env=env, timeout=timeout)
        if check and value.returncode: raise Failure('scratch_' + command[0] + '_' + str(value.returncode))
        return value

    def sql(statement):
        return run(['docker', 'exec', '-i', name, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'wallet_restore'], statement.encode()).stdout.decode().strip()

    started = False
    try:
        run(['docker', 'run', '-d', '--name', name, '--network', 'none', '--user', 'postgres',
             '--read-only', '--tmpfs', '/var/lib/postgresql/data:uid=999,gid=999',
             '--tmpfs', '/var/run/postgresql:uid=999,gid=999,mode=3775', '--tmpfs', '/tmp:size=16m,mode=1777',
             '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '512m', '--cpus', '0.5', '--pids-limit', '128',
             '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB',
             'postgres:17.6-bookworm@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3'])
        started = True
        for _ in range(60):
            if run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], check=False).returncode == 0: break
            time.sleep(.25)
        else: raise Failure('offline_scratch_db_not_ready')
        run(['docker', 'exec', '-i', name, 'pg_restore', '--exit-on-error', '--no-owner', '--no-acl', '-U', 'postgres', '-d', 'wallet_restore'], dump, timeout=120)
        applied = {}
        for row in sql("SELECT version,success,encode(checksum,'hex') FROM _sqlx_migrations ORDER BY version").splitlines():
            version, success, checksum = row.split('|')
            if success != 't': raise Failure('restored_migration_unsuccessful')
            applied[int(version)] = checksum
        files = run(['git', 'ls-tree', '-r', '--name-only', last['observed_health_source_sha'], 'api/migrations']).stdout.decode().splitlines()
        expected_migrations = {}
        for filename in files:
            if filename.endswith('.sql'):
                body = run(['git', 'show', last['observed_health_source_sha'] + ':' + filename]).stdout
                expected_migrations[int(Path(filename).name.split('_')[0])] = hashlib.sha384(body).hexdigest()
        if applied != expected_migrations or max(applied) != last['observed_health_migration']:
            raise Failure('restored_history_not_exact_pinned_source')
        counts = dict(zip(['profiles', 'wallets', 'assignments', 'contacts'], map(int, sql(
            'SELECT (SELECT count(*) FROM profiles),(SELECT count(*) FROM wallets),(SELECT count(*) FROM assignments),(SELECT count(*) FROM contacts)').split('|'))))
        timers_before = sql("SELECT COALESCE(jsonb_agg(jsonb_build_array(proposed_at,executable_at,delay_seconds,accepted_at,cancelled_at,removal_at) ORDER BY id),'[]'::jsonb) FROM assignments")
        # Version-independent audit/lease/transport preservation: include every
        # present field except the unchanged opaque encrypted payload.
        outbox_query = "SELECT COALESCE(jsonb_agg(to_jsonb(o)-'encrypted_payload' ORDER BY id),'[]'::jsonb) FROM notification_outbox o"
        outbox_before = sql(outbox_query)
        smtp_evidence = None
        if max(applied) >= 6:
            smtp_evidence = json.loads(sql("SELECT jsonb_build_object('total_outbox_rows',count(*),'smtp_sent_with_first_attempt',count(*) FILTER (WHERE delivery_transport='smtp' AND state='sent' AND first_attempt_at IS NOT NULL AND sent_at IS NOT NULL),'smtp_attempted_with_first_attempt',count(*) FILTER (WHERE delivery_transport='smtp' AND attempts>0 AND first_attempt_at IS NOT NULL)) FROM notification_outbox"))
        if args.min_smtp_sent_with_first_attempt and (smtp_evidence is None or smtp_evidence['smtp_sent_with_first_attempt'] < args.min_smtp_sent_with_first_attempt):
            raise Failure('restored_smtp_delivery_metadata_evidence_insufficient')
        owned_trial_sessions = owned_trial_session_counter(sql, last['stamp']) if owned_trial_session_counter else None
        # Exercise incident-promotion auth invalidation only in this scratch DB.
        sql('BEGIN; DELETE FROM sessions; DELETE FROM challenges; DELETE FROM contact_verifications; COMMIT;')
        if sql('SELECT (SELECT count(*) FROM sessions)+(SELECT count(*) FROM challenges)+(SELECT count(*) FROM contact_verifications)') != '0':
            raise Failure('scratch_auth_replay_invalidation_failed')
        if timers_before != sql("SELECT COALESCE(jsonb_agg(jsonb_build_array(proposed_at,executable_at,delay_seconds,accepted_at,cancelled_at,removal_at) ORDER BY id),'[]'::jsonb) FROM assignments"):
            raise Failure('original_timer_evidence_changed')
        if outbox_before != sql(outbox_query):
            raise Failure('attempt_or_uncertainty_evidence_changed')
        # Fresh recovered contact key, owned API-format nonce+ciphertext canary.
        nonce = secrets.token_bytes(12); marker = b'owned-offhost-contact-canary.invalid'
        encrypted = nonce + AESGCM(bytes.fromhex(recovery['contact_encryption_key'])).encrypt(nonce, marker, None)
        encoded = encrypted.hex()
        sql("INSERT INTO profiles(id,anchor_wallet) VALUES('00000000-0000-0000-0000-000000000099','owned-offhost-scratch-canary') ON CONFLICT(id) DO NOTHING; "
            "INSERT INTO contacts(id,profile_id,kind,encrypted_destination) VALUES('00000000-0000-0000-0000-000000000099','00000000-0000-0000-0000-000000000099','email',decode('" + encoded + "','hex'));")
        recovered_bytes = bytes.fromhex(sql("SELECT encode(encrypted_destination,'hex') FROM contacts WHERE id='00000000-0000-0000-0000-000000000099'"))
        if AESGCM(bytes.fromhex(recovery['contact_encryption_key'])).decrypt(recovered_bytes[:12], recovered_bytes[12:], None) != marker:
            raise Failure('scratch_contact_key_canary_failed')
        receipt = {'offhost_cipher_sha256': expected, 'schema_source_commit_checked': last['observed_health_source_sha'], 'migration': max(applied),
            'exact_sqlx_checksums': True, 'aggregate_restored_counts': counts,
            'aggregate_restored_smtp_evidence': smtp_evidence,
            'minimum_required_smtp_sent_with_first_attempt': args.min_smtp_sent_with_first_attempt,
            'owned_trial_sessions_before_scratch_auth_invalidation': owned_trial_sessions,
            'fresh_vault_age_decryption': True, 'fresh_contact_key_api_format_canary': True,
            'scratch_all_sessions_challenges_contact_tokens_invalidated': True,
            'original_timer_and_outbox_attempt_uncertainty_evidence_preserved': True,
            'delivery_and_chain_workers_started': False, 'production_data_or_auth_mutated': False,
            'promoted_to_live': False, 'private_key_files_or_arguments_used': False, 'custody_version': metadata.get('version')}
        print(json.dumps(receipt, sort_keys=True))
        write_path = Path(args.config).with_name('last-offhost-restore-receipt.json')
        from backup_control import write_private
        write_private(write_path, receipt)
    finally:
        if started: run(['docker', 'rm', '-f', name], check=False)


if __name__ == '__main__': safe_main(main)
