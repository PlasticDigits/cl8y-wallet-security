#!/usr/bin/env python3
"""Manage only the separate credential-free mail gateway. API credentials stay in memory."""
import argparse
import json
import os
import re
import subprocess
import urllib.error
import urllib.request

NAME = 'wallet-security-mail-gateway'
REPO = 'https://git.cl8y.com/code/cl8y-wallet-security.git'
PROJECT = 'lp68vobuzjopuxchbhywulm7'
SERVER = 'ezqivkqptuds8gjnvfuw18jx'
ENVIRONMENT = 'edyowcbvthpkkugp7qwcjxxo'
DESTINATION = 'n3nyhm5drw6a6plmcbjgjj3k'
PORTAL = 'qri1j8vhtwwb9akyxfiw73gc'
COMPOSE = '/deploy/mail-gateway/compose.yml'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def api(method, path, data=None):
    request = urllib.request.Request(os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1' + path,
        method=method, data=None if data is None else json.dumps(data).encode(),
        headers={'Authorization':'Bearer '+os.environ['COOLIFY_WIRE_TOKEN'],
                 'Content-Type':'application/json', 'Accept':'application/json'})
    with OPENER.open(request, timeout=20) as response:
        content = response.read(8_000_001)
        if len(content) > 8_000_000: raise RuntimeError('response_bound')
        return json.loads(content) if content else None

def identifier(value):
    if not isinstance(value, str) or not re.fullmatch('[a-z0-9]{20,32}', value):
        raise RuntimeError('identifier_invalid')
    return value

def owned(app):
    identifier(app)
    if app == PORTAL: raise RuntimeError('portal_refused')
    d = api('GET', '/applications/' + app)
    if d.get('name') != NAME or d.get('git_repository') != REPO or d.get('docker_compose_location') != COMPOSE:
        raise RuntimeError('resource_identity_conflict')
    if d.get('environment', {}).get('uuid') != ENVIRONMENT or d.get('destination', {}).get('uuid') != DESTINATION:
        raise RuntimeError('resource_scope_conflict')
    return d

def commands(app, sha):
    identifier(app)
    if app == PORTAL or not re.fullmatch('[a-f0-9]{40}',sha): raise RuntimeError('command_identity_invalid')
    build='SOURCE_SHA='+sha+' timeout 55 docker compose -f deploy/mail-gateway/compose.yml build gateway'
    start='timeout 65 bash deploy/mail-gateway/launch.sh '+app+' '+sha
    if max(len(build.encode()),len(start.encode())) > 255: raise RuntimeError('command_bound')
    return build,start

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--create', action='store_true')
    p.add_argument('--app')
    p.add_argument('--sha')
    p.add_argument('--branch')
    p.add_argument('--deployment')
    p.add_argument('--receipts', action='store_true')
    a = p.parse_args()
    if a.receipts and not a.deployment: raise RuntimeError('deployment_required')
    if a.create:
        if a.app or a.deployment or a.receipts: raise RuntimeError('operation_conflict')
    elif not a.app: raise RuntimeError('app_required')
    if a.create or not (a.deployment or a.receipts):
        if not a.sha or not re.fullmatch('[0-9a-f]{40}', a.sha) or not a.branch or not re.fullmatch('[a-zA-Z0-9_./-]{1,180}', a.branch):
            raise RuntimeError('source_pin_required')
        commands(a.app or 'a'*32,a.sha)
        result = subprocess.run(['git','ls-remote',REPO,'refs/heads/'+a.branch],capture_output=True,text=True,timeout=20)
        if result.returncode or not result.stdout.startswith(a.sha+'\t'): raise RuntimeError('source_pin_mismatch')
    if a.create:
        items = api('GET','/applications')
        if isinstance(items, dict): items=items.get('data',[])
        if any(x.get('name') == NAME for x in items): raise RuntimeError('gateway_already_exists')
        d = api('POST','/applications/public',dict(project_uuid=PROJECT,server_uuid=SERVER,
            environment_uuid=ENVIRONMENT,destination_uuid=DESTINATION,name=NAME,
            git_repository=REPO,git_branch=a.branch,git_commit_sha=a.sha,build_pack='dockercompose',
            docker_compose_location=COMPOSE,ports_exposes='1587',instant_deploy=False,
            is_raw_compose_deployment_enabled=True,is_auto_deploy_enabled=False,
            is_preview_deployments_enabled=False,inject_build_args_to_dockerfile=False,
            include_coolify_default_variables=False,redact_all_env_values_in_logs=True))
        print(json.dumps({'gateway_created':True,'application_uuid':identifier(d.get('uuid')),'deployed':False}))
        return
    d=owned(a.app)
    if a.deployment:
        deployment=api('GET','/deployments/'+identifier(a.deployment))
        if deployment.get('application_name') != NAME: raise RuntimeError('deployment_scope_conflict')
        status=deployment.get('status')
        if status not in ('queued','in_progress','finished','failed','cancelled'): raise RuntimeError('status_invalid')
        if a.receipts:
            logs=deployment.get('logs',[])
            if isinstance(logs,str): logs=json.loads(logs)
            if not isinstance(logs,list): raise RuntimeError('logs_shape_invalid')
            patterns=[r'mail_gateway_tls_window start_utc=[0-9]{8}T[0-9]{6}Z end_utc=[0-9]{8}T[0-9]{6}Z ehlo=cl8y-gateway-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}', r'mail_gateway_preflight_pass uid=10001 no_default_route=true alias_private=true hostname_verified=true direct_mailu_denied=true other_targets_denied=true auth=false sends=0',
                r'mail_gateway_runtime_pass source_sha=[a-f0-9]{40} running_image_ref=sha256:[a-f0-9]{64} built_config_digest=sha256:[a-f0-9]{64} uid=10001 ports=0 mounts=0 credentials=false networks=2 memory_bytes=67108864 nano_cpus=100000000 pids=16 nnp=true worker_direct_egress_denied=true',
                r'mail_gateway_(?:preflight|runtime)_failed stage=(?:identity|routes|direct_denial|alias|tls|credentials|networks|resource_bounds|worker_denial|tls_probe|receipt)']
            for item in logs:
                if not isinstance(item,dict): continue
                output=item.get('output')
                if not isinstance(output,str): continue
                for line in output.splitlines():
                    if any(re.fullmatch(pattern,line) for pattern in patterns): print(line)
        else:
            print(json.dumps({'application_uuid':a.app,'deployment_uuid':a.deployment,'status':status}))
        return
    build,start=commands(a.app,a.sha)
    envs=api('GET','/applications/'+a.app+'/envs')
    if any(x.get('key') != 'SOURCE_SHA' for x in envs): raise RuntimeError('unexpected_runtime_env')
    api('PATCH' if envs else 'POST','/applications/'+a.app+'/envs',dict(key='SOURCE_SHA',value=a.sha,is_buildtime=True,is_runtime=True,is_literal=True))
    settings=dict(git_branch=a.branch,git_commit_sha=a.sha,is_raw_compose_deployment_enabled=True,
        is_preserve_repository_enabled=True,is_auto_deploy_enabled=False,is_preview_deployments_enabled=False,
        inject_build_args_to_dockerfile=False,include_coolify_default_variables=False,redact_all_env_values_in_logs=True,
        docker_compose_custom_build_command=build,docker_compose_custom_start_command=start)
    api('PATCH','/applications/'+a.app,settings)
    actual=owned(a.app)
    flags=actual.get('settings',{})
    if not flags.get('is_raw_compose_deployment_enabled') or flags.get('inject_build_args_to_dockerfile') is not False or actual.get('docker_compose_custom_start_command') != start or actual.get('docker_compose_custom_build_command') != build:
        raise RuntimeError('raw_boundary_not_applied')
    result=api('POST','/deploy',{'uuid':a.app,'force':False})
    ids=[identifier(x.get('deployment_uuid')) for x in result.get('deployments',[])]
    print(json.dumps({'application_uuid':a.app,'source_sha':a.sha,'deployment_uuids':ids}))

if __name__ == '__main__':
    try:main()
    except Exception:
        print('mail_gateway_operation_failed_no_raw_output')
        raise SystemExit(1) from None
