#!/usr/bin/env python3
"""Pin/release only this portal; credentials come from bao-exec environment.

No API response containing configuration, environment values or logs is printed.
The CLI uses only resource IDs and public source identity as arguments.
"""
import argparse
import json
import os
import re
import subprocess
import urllib.error
import urllib.request

SECRETS = ('POSTGRES_PASSWORD', 'DB_MIGRATOR_PASSWORD', 'DB_API_PASSWORD',
           'DB_WORKER_PASSWORD', 'DB_BACKUP_PASSWORD', 'CONTACT_ENCRYPTION_KEY')
RECEIPT = re.compile(r'(?:runtime_boundary_pass mode=(?:api|worker) uid=10001 admin_env_absent=true ddl_denied=true migration_write_denied=true|restore_drill_pass migration=\d+ public_tables=\d+ archive_sha256=[a-f0-9]{64} owned_profiles=[01] owned_events=[01]|backup_complete utc=\d{8}T\d{6}Z)')


def api(method, path, data=None):
    base = os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1'
    request = urllib.request.Request(base + path, method=method,
        data=None if data is None else json.dumps(data).encode(),
        headers={'Authorization': 'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'],
                 'Content-Type': 'application/json', 'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            content = response.read()
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as error:
        # Never print error bodies: validation can echo submitted secrets.
        raise SystemExit(f'Coolify {method} failed HTTP {error.code}') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True)
    parser.add_argument('--branch')
    parser.add_argument('--sha')
    parser.add_argument('--image-digest', help='Reuse the already tested public OCI manifest')
    parser.add_argument('--runtime-hook-sha', default='b8aa303154b25d3017816c258b0daeb8954b7b26',
                        help='Exact reviewed deployment hook preserving unique private DB DNS')
    parser.add_argument('--postgres-only', action='store_true')
    parser.add_argument('--deployment', help='Read only this deployment status')
    parser.add_argument('--receipts', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch('[a-z0-9]{20,32}', args.app):
        parser.error('invalid resource identifier')
    application = api('GET', '/applications/' + args.app)
    if application.get('name') != 'cl8y-wallet-security':
        raise SystemExit('Refusing a resource outside this portal')
    if args.deployment:
        if not re.fullmatch('[a-z0-9]{20,32}', args.deployment):
            parser.error('invalid deployment identifier')
        deployment = api('GET', '/deployments/' + args.deployment)
        owner = deployment.get('application')
        owner_uuid = owner.get('uuid') if isinstance(owner, dict) else None
        if owner_uuid and owner_uuid != args.app:
            raise SystemExit('Deployment does not belong to this portal')
        if not owner_uuid:
            # API can omit internal numeric IDs; public application_name still binds the operation.
            if deployment.get('application_name') != 'cl8y-wallet-security':
                raise SystemExit('Deployment does not belong to this portal')
        print(json.dumps({key: deployment.get(key) for key in
              ('deployment_uuid', 'status', 'commit', 'created_at', 'finished_at')}))
        return
    if args.receipts:
        for service in ('api', 'worker', 'backup', 'restore-drill'):
            result = api('GET', '/applications/' + args.app + '/logs?service_name=' + service + '&lines=100')
            for receipt in RECEIPT.findall(json.dumps(result)):
                print(receipt)
        return
    if not args.branch or not args.sha or not re.fullmatch('[0-9a-f]{40}', args.sha):
        parser.error('release requires a branch and exact 40-character reviewed SHA')
    remote = subprocess.run(['git', 'ls-remote', 'https://git.cl8y.com/code/cl8y-wallet-security.git',
                             'refs/heads/' + args.branch], capture_output=True, text=True, timeout=40, check=True)
    if not remote.stdout.startswith(args.sha + '\t'):
        raise SystemExit('Published branch tip differs from requested reviewed SHA')
    envs = api('GET', '/applications/' + args.app + '/envs')
    production = {item['key']: item for item in envs if not item.get('is_preview')}
    for key in SECRETS:
        if key not in production or not production[key].get('value'):
            raise SystemExit('Required protected runtime secret absent: ' + key)
        api('PATCH', '/applications/' + args.app + '/envs',
            {'key': key, 'is_buildtime': False, 'is_runtime': True, 'is_literal': True})
    for key in production:
        if key != 'SOURCE_SHA':
            api('PATCH', '/applications/' + args.app + '/envs', {'key': key, 'is_buildtime': False})
    api('PATCH', '/applications/' + args.app + '/envs',
        {'key': 'SOURCE_SHA', 'value': args.sha, 'is_buildtime': True, 'is_runtime': True})
    api('PATCH', '/applications/' + args.app + '/envs',
        {'key': 'PUBLIC_ORIGIN', 'value': 'https://security.cl8y.com', 'is_buildtime': False, 'is_runtime': True})
    build_service = 'postgres' if args.postgres_only else 'api'
    start_suffix = ' postgres' if args.postgres_only else ''
    if not re.fullmatch('[0-9a-f]{40}', args.runtime_hook_sha):
        parser.error('exact reviewed runtime hook SHA required')
    # Keep the unique API database hostname on every release: the shared proxy
    # network has an unrelated "postgres" alias. The hook writes only a literal
    # secret reference, then interpolates it through Coolify's protected runtime.
    if args.postgres_only:
        start = ('timeout 180 docker compose --env-file .env -f compose.yml --project-directory '
                 '/data/coolify/applications/' + args.app + ' --project-name ' + args.app
                 + ' up -d --no-build' + start_suffix)
    else:
        hook_url = ('https://git.cl8y.com/code/cl8y-wallet-security/raw/commit/'
                    + args.runtime_hook_sha + '/deploy/runtime-overlay.sh')
        start = ("timeout 180 bash -o pipefail -c 'curl -fsS " + hook_url + ' | bash -s -- '
                 + args.app + ' ' + args.sha + "'")
    build = 'timeout 900 docker compose build ' + build_service
    if args.image_digest:
        if not re.fullmatch('sha256:[0-9a-f]{64}', args.image_digest):
            parser.error('exact OCI manifest digest required')
        registry = 'git.cl8y.com/code/cl8y-wallet-security@' + args.image_digest
        build = ("timeout 300 sh -c 'im=" + registry
                 + '; docker pull "$im" && docker tag "$im" wallet-security:' + args.sha + "'")
    if len(start) > 255 or len(build) > 255:
        raise SystemExit('Coolify custom command exceeds its observed storage limit')
    api('PATCH', '/applications/' + args.app, {
        'git_branch': args.branch, 'git_commit_sha': args.sha,
        'is_raw_compose_deployment_enabled': True, 'is_preserve_repository_enabled': True,
        'is_auto_deploy_enabled': False, 'is_preview_deployments_enabled': False,
        'inject_build_args_to_dockerfile': False, 'redact_all_env_values_in_logs': True,
        'include_coolify_default_variables': False,
        'docker_compose_custom_build_command': build,
        'docker_compose_custom_start_command': start})
    actual = api('GET', '/applications/' + args.app)
    settings = actual.get('settings', {})
    if not settings.get('is_raw_compose_deployment_enabled') or settings.get('inject_build_args_to_dockerfile') is not False:
        raise SystemExit('Required raw/ARG-injection boundary settings not applied')
    if actual.get('docker_compose_custom_start_command') != start or actual.get('docker_compose_custom_build_command') != build:
        raise SystemExit('Pinned deployment hook/build command readback differs')
    envs = api('GET', '/applications/' + args.app + '/envs')
    production = {item['key']: item for item in envs if not item.get('is_preview')}
    if not all(production[key].get('is_runtime') and not production[key].get('is_buildtime') for key in SECRETS):
        raise SystemExit('Required runtime-only secret flags not applied')
    if any(item.get('is_buildtime') for key, item in production.items() if key != 'SOURCE_SHA'):
        raise SystemExit('Unexpected build-time variable; refusing credential argument injection')
    deployment = api('POST', '/deploy', {'uuid': args.app, 'force': False})
    print(json.dumps({'application_uuid': args.app, 'source_sha': args.sha,
                      'scope': 'postgres_only' if args.postgres_only else 'full',
                      'deployment_uuids': [item.get('deployment_uuid') for item in deployment.get('deployments', [])]}))


if __name__ == '__main__':
    main()
