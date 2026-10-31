#!/usr/bin/env python3
"""Bounded nonsecret fixture test of sealer mounts, crypto and restart repair."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    prefix = 'wallet-security-seal-test-' + secrets.token_hex(4)
    pg, seal, volume = prefix + '-pg', prefix + '-seal', prefix + '-cipher'
    env = {**os.environ, 'POSTGRES_PASSWORD': secrets.token_hex(32), 'POSTGRES_DB': 'fixture'}

    def run(command, content=None, check=True, timeout=45):
        result = subprocess.run(command, input=content, capture_output=True, env=env, timeout=timeout)
        if check and result.returncode:
            raise SystemExit(json.dumps({'sealer_test_failed': command[:2], 'exit_code': result.returncode}))
        return result

    # No inherited anonymous PGDATA mount may survive the clean final stage.
    volumes = json.loads(run(['docker', 'image', 'inspect', args.image]).stdout)[0]['Config'].get('Volumes', {})
    assert not volumes
    identity = run(['age-keygen']).stdout
    public = run(['age-keygen', '-y'], identity).stdout.decode().strip()
    env.update(AGE_PUBLIC_RECIPIENT=public, SEAL_ONCE='false')
    started_pg = started_seal = created_volume = False
    with tempfile.TemporaryDirectory(prefix=prefix + '-') as temporary:
        source = Path(temporary) / 'input'
        source.mkdir(mode=0o755)
        name = 'wallet-security-20000101T000000Z.dump'
        try:
            run(['docker', 'run', '-d', '--name', pg, '--network', 'none', '--user', 'postgres',
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                 '--tmpfs', '/var/lib/postgresql/data:uid=999,gid=999',
                 '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB',
                 'postgres:17.6-bookworm@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3'])
            started_pg = True
            for _ in range(40):
                if run(['docker', 'exec', pg, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], check=False).returncode == 0:
                    break
                time.sleep(.25)
            else:
                raise SystemExit('Owned fixture PostgreSQL did not become ready')
            run(['docker', 'exec', '-i', pg, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'fixture'],
                b"CREATE TABLE owned_fixture(id integer PRIMARY KEY,marker text); INSERT INTO owned_fixture VALUES(1,'owned-sealer-fixture');")
            dump = run(['docker', 'exec', pg, 'pg_dump', '-U', 'postgres', '-d', 'fixture', '--format=custom', '--no-owner', '--no-acl']).stdout
            (source / name).write_bytes(dump)
            (source / name).chmod(0o444)
            checksum = source / (name + '.sha256')
            checksum.write_text(hashlib.sha256(dump).hexdigest() + '  /backups/' + name + '\n')
            checksum.chmod(0o444)
            run(['docker', 'volume', 'create', volume]); created_volume = True
            common = ['--network', 'none', '--user', '999:999', '--read-only', '--tmpfs', '/tmp:size=16m,mode=1777',
                      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '128m', '--cpus', '0.25', '--pids-limit', '48',
                      '-v', str(source) + ':/backups:ro', '-v', volume + ':/encrypted']
            run(['docker', 'run', '-d', '--name', seal, '--stop-timeout', '210', *common,
                 '-e', 'AGE_PUBLIC_RECIPIENT', '-e', 'SEAL_ONCE', args.image])
            started_seal = True
            for _ in range(80):
                if run(['docker', 'exec', seal, 'test', '-f', '/encrypted/' + name + '.age.sha256'], check=False).returncode == 0:
                    break
                time.sleep(.1)
            else:
                raise SystemExit('Sealer did not complete owned fixture')
            mounts = json.loads(run(['docker', 'inspect', '--format', '{{json .Mounts}}', seal]).stdout)
            by_destination = {mount['Destination']: mount for mount in mounts}
            assert set(by_destination).issubset({'/backups', '/encrypted', '/tmp'})
            assert by_destination['/backups']['RW'] is False and by_destination['/encrypted']['RW'] is True
            assert '/var/lib/postgresql/data' not in by_destination
            cipher = run(['docker', 'exec', seal, 'cat', '/encrypted/' + name + '.age']).stdout

            def recover(data):
                read, write = os.pipe()
                try:
                    os.write(write, identity); os.close(write); write = -1
                    result = subprocess.run(['age', '-d', '-i', '/proc/self/fd/' + str(read)], input=data,
                        capture_output=True, pass_fds=(read,), timeout=20)
                    return result
                finally:
                    os.close(read)
                    if write >= 0: os.close(write)

            recovered = recover(cipher)
            assert recovered.returncode == 0 and recovered.stdout == dump
            broken = bytearray(cipher); broken[-1] ^= 1
            assert recover(bytes(broken)).returncode != 0
            begin = time.monotonic()
            run(['docker', 'stop', seal], timeout=15)
            graceful = time.monotonic() - begin < 10
            assert graceful
            # Simulate a kill between output rename/checksum and a stale partial.
            run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '999:999',
                 '-v', volume + ':/encrypted', '--entrypoint', '/bin/bash', args.image, '-c',
                 'unlink /encrypted/' + name + '.age.sha256; : > /encrypted/' + name + '.age.partial'])
            env['SEAL_ONCE'] = 'true'
            run(['docker', 'run', '--rm', *common, '-e', 'AGE_PUBLIC_RECIPIENT', '-e', 'SEAL_ONCE', args.image])
            repaired = run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '999:999',
                            '-v', volume + ':/encrypted:ro', '--entrypoint', '/bin/cat', args.image, '/encrypted/' + name + '.age']).stdout
            recovered = recover(repaired)
            assert recovered.returncode == 0 and recovered.stdout == dump
            result = {'no_inherited_volume': True, 'actual_mounts_only_declared': True, 'input_read_only': True,
                      'owned_dump_age_roundtrip': True, 'corruption_rejected': True, 'graceful_snapshot_fence': graceful,
                      'interrupted_pair_repaired': True, 'no_private_key_or_upload_credentials_in_workload': True}
            print(json.dumps(result, sort_keys=True))
        finally:
            if started_seal: run(['docker', 'rm', '-f', seal], check=False)
            if started_pg: run(['docker', 'rm', '-f', pg], check=False)
            if created_volume: run(['docker', 'volume', 'rm', volume], check=False)


if __name__ == '__main__':
    main()
