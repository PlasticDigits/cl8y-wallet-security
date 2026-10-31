"""Fresh closed daemon/private-listener attestation before any ciphertext GET."""
import datetime as dt
import json
import re
import time
from pathlib import Path
import yaml
from backup_control import Failure, identifier


def verify_records(output,config):
    lines=output.splitlines()
    image=re.findall(r'^WG_OBS_IMAGE reference=(sha256:[0-9a-f]{64}) source=([0-9a-f]{40})$',output,re.M)
    if not image or any(ref!=config['export_image'].split('@')[1] or sha!=config['export_source_sha'] for ref,sha in image):
        raise Failure('actual_export_image_or_source_differs')
    expected='WG_OBS_HOST user=999:999 running=true network=host memory=67108864 cpu=100000000 pids=16 readonly=true ports=0'
    host=[line for line in lines if line.startswith('WG_OBS_HOST ')]
    if not host or set(host)!={expected}:raise Failure('actual_export_runtime_boundary_differs')
    mounts=set(line for line in lines if line.startswith('WG_OBS_MOUNT '))
    if mounts!={'WG_OBS_MOUNT volume '+config['resolved_sealed_volume']+' /export false'}:
        raise Failure('actual_export_mount_scope_differs')
    if set(line for line in lines if line.startswith('WG_OBS_CAPDROP '))!={'WG_OBS_CAPDROP ALL'}:
        raise Failure('actual_export_capabilities_differ')
    if set(line for line in lines if line.startswith('WG_OBS_SECURITY '))!={'WG_OBS_SECURITY no-new-privileges:true'}:
        raise Failure('actual_export_security_options_differ')
    listeners=set(line for line in lines if line.startswith('WG_OBS_LISTEN '))
    if listeners!={'WG_OBS_LISTEN 0100080A:470C'}:
        raise Failure('actual_export_not_private_only_listener')
    groups=re.findall(r'^WG_OBS_ENV_NAMES_BEGIN\n(.*?)^WG_OBS_ENV_NAMES_END$',output,re.M|re.S)
    if not groups:raise Failure('actual_export_environment_unobserved')
    required={'EXPORT_TOKEN','EXPECTED_CIPHER_SHA256','EXPORT_FILENAME','EXPORT_EXPIRES_UNIX'}
    for group in groups:
        names={line for line in group.splitlines() if line != ''}
        if not required.issubset(names):raise Failure('actual_export_required_purpose_env_absent')
        for name in names:
            if name in required or name=='PATH':continue
            if (not name.startswith(('COOLIFY_','SERVICE_NAME_'))
                or any(part in name.upper() for part in ['TOKEN','PASSWORD','PRIVATE','KEY','DATABASE','AWS','BAO'])):
                raise Failure('actual_export_forbidden_environment_name')
    if 'WG_OBS_COMPLETE read_only=true' not in lines:raise Failure('actual_export_observation_incomplete')
    return {'actual_image_source_bound':True,'private_listener_only_verified':True,'actual_ro_owned_cipher_mount':True,
            'actual_uid_limits_caps_nnp_verified':True,'forbidden_credentials_absent':True}


def inspector_guard(api, config, resource, expected_build='/bin/false'):
    destination=resource.get('destination') or {};settings=resource.get('settings') or {}
    expected=yaml.safe_load(Path(__file__).with_name('backup-inspector').joinpath('compose.yml').read_text())
    stopped={'exited','stopped','exited:unknown','exited:healthy','exited:unhealthy'}
    if (resource.get('uuid')!=config['inspector_app_uuid'] or resource.get('name')!=config['inspector_name']
        or resource.get('environment_id')!=config['resource_context']['environment_id']
        or resource.get('destination_id')!=config['resource_context']['destination_id']
        or destination.get('uuid')!=config['destination_uuid']
        or (destination.get('server') or {}).get('uuid')!=config['server_uuid']
        or resource.get('git_repository')!='https://git.cl8y.com/code/cl8y-wallet-security.git'
        or resource.get('git_commit_sha')!=config['inspector_source_sha']
        or resource.get('git_branch')!=config['inspector_source_branch']
        or resource.get('build_pack')!='dockercompose'
        or resource.get('docker_compose_location')!='/deploy/backup-inspector/compose.yml'
        or resource.get('docker_compose_custom_start_command')!='/bin/false'
        or resource.get('docker_compose_custom_build_command')!=expected_build
        or yaml.safe_load(resource.get('docker_compose_raw') or '')!=expected
        or resource.get('status') not in stopped
        or settings.get('is_raw_compose_deployment_enabled') is not True
        or settings.get('is_preserve_repository_enabled') is not True
        or settings.get('is_auto_deploy_enabled') is not False
        or settings.get('is_preview_deployments_enabled') is not False
        or settings.get('inject_build_args_to_dockerfile') is not False
        or settings.get('include_coolify_default_variables') is not False
        or api.call('GET','/applications/'+config['inspector_app_uuid']+'/envs')):
        raise Failure('operator_observer_actual_scope_or_runtime_differs')


def observe(api,config,exporter,fence):
    observer=api.call('GET','/applications/'+identifier(config['inspector_app_uuid']))
    inspector_guard(api,config,observer)
    # Literal reviewed imported-source hook: no pipe/operator parsing and no
    # dependency on the .git directory that Coolify strips from build artifacts.
    command='timeout 60 bash ./deploy/cipher-export/inspect.sh '+identifier(exporter)
    if len(command)>255:raise Failure('operator_observation_command_too_long')
    fence();prefix='/applications/'+config['inspector_app_uuid']
    api.call('PATCH',prefix,{'docker_compose_custom_build_command':command})
    if api.call('GET',prefix).get('docker_compose_custom_build_command')!=command:
        raise Failure('operator_observer_command_readback_differs')
    inspector_guard(api,config,api.call('GET',prefix),command)
    started=dt.datetime.now(dt.timezone.utc)
    queued=api.call('POST','/deploy',{'uuid':config['inspector_app_uuid'],'force':False})
    entries=queued.get('deployments',[])
    if len(entries)!=1:raise Failure('operator_observation_dispatch_ambiguous')
    deployment=identifier(entries[0]['deployment_uuid']);deadline=time.monotonic()+90
    try:
        while time.monotonic()<deadline:
            fence();result=api.call('GET','/deployments/'+deployment)
            if result.get('commit') not in [None,config['inspector_source_sha']]:raise Failure('observer_execution_source_differs')
            if result.get('status') in ['failed','finished']:
                rows=json.loads(result.get('logs') or '[]')
                output='\n'.join(str(row.get('output','')) for row in rows if isinstance(row,dict))
                proof=verify_records(output,config);proof['operator_observation_job']=deployment
                proof['observed_at']=dt.datetime.now(dt.timezone.utc).isoformat()
                return proof
            time.sleep(1)
        raise Failure('operator_observation_deadline')
    finally:
        # Stopped inspector never needs a deployment/runtime after this read.
        api.call('PATCH',prefix,{'docker_compose_custom_build_command':'/bin/false'})
