#!/usr/bin/env python3
"""Create only a stopped operator observation resource; no runtime/credential."""
import argparse
import json
from pathlib import Path
import re
from backup_control import Api, Failure, identifier, safe_main, validate_sealer, write_private


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    parser.add_argument('--observer-source',required=True)
    parser.add_argument('--source-branch',required=True)
    args=parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}',args.observer_source):raise Failure('invalid_observer_source')
    path=Path(args.config);config=json.loads(path.read_text());api=Api();validate_sealer(api,config)
    name='wallet-security-backup-inspector-'+config['portal_app_uuid'][:8]
    if config.get('inspector_app_uuid'):
        resource=api.call('GET','/applications/'+identifier(config['inspector_app_uuid']))
    else:
        found=[item for item in api.call('GET','/applications') if item.get('name')==name]
        if len(found)>1:raise Failure('ambiguous_observer_resource')
        if found:resource=api.call('GET','/applications/'+identifier(found[0]['uuid']))
        else:
            resource=api.call('POST','/applications/public',{'name':name,'project_uuid':config['project_uuid'],
                'environment_uuid':config['environment_uuid'],'server_uuid':config['server_uuid'],
                'destination_uuid':config['destination_uuid'],'git_repository':'https://git.cl8y.com/code/cl8y-wallet-security.git',
                'git_branch':args.source_branch,'git_commit_sha':args.observer_source,'build_pack':'dockercompose',
                'docker_compose_location':'/deploy/backup-inspector/compose.yml','instant_deploy':False,
                'is_auto_deploy_enabled':False,'is_preview_deployments_enabled':False,
                'is_raw_compose_deployment_enabled':True,'is_preserve_repository_enabled':True,
                'inject_build_args_to_dockerfile':False,'include_coolify_default_variables':False,
                'redact_all_env_values_in_logs':True,'docker_compose_custom_build_command':'/bin/false',
                'docker_compose_custom_start_command':'/bin/false'})
            resource=api.call('GET','/applications/'+identifier(resource['uuid']))
    destination=resource.get('destination') or {};settings=resource.get('settings') or {}
    if (resource.get('name')!=name or any(resource.get(k)!=v for k,v in config['resource_context'].items() if k!='server_id')
        or destination.get('uuid')!=config['destination_uuid']
        or (destination.get('server') or {}).get('uuid')!=config['server_uuid']
        or resource.get('git_commit_sha')!=args.observer_source or resource.get('build_pack')!='dockercompose'
        or not settings.get('is_raw_compose_deployment_enabled') or settings.get('is_auto_deploy_enabled')
        or settings.get('is_preview_deployments_enabled') or settings.get('inject_build_args_to_dockerfile') is not False):
        raise Failure('observer_actual_scope_or_source_differs')
    config.update(inspector_app_uuid=resource['uuid'],inspector_name=name,inspector_source_sha=args.observer_source)
    write_private(path,config)
    print(json.dumps({'stopped_readonly_observer_resource_prepared':True,'resource_uuid':resource['uuid'],
        'source_sha':args.observer_source,'deployment_requested':False,'runtime_or_credentials_supplied':False}))


if __name__=='__main__':safe_main(main)
