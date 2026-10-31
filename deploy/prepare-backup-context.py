#!/usr/bin/env python3
"""Read-only scope validation and private metadata preparation, no secret data."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import yaml
from backup_control import Api, Failure, safe_main, write_private


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--observed-output-volume', required=True)
    parser.add_argument('--observed-image-manifest', required=True)
    args = parser.parse_args()
    path = Path(args.config); config = json.loads(path.read_text()); api = Api()
    spec = importlib.util.spec_from_file_location('sealer_scope', Path(__file__).with_name('provision-backup-sealer.py'))
    scope = importlib.util.module_from_spec(spec); spec.loader.exec_module(scope)
    portal = api.call('GET', '/applications/' + config['portal_app_uuid'])
    project = api.call('GET', '/projects/' + config['project_uuid'])
    matches = [item for item in project.get('environments', []) if item.get('id') == portal.get('environment_id')]
    if len(matches) != 1: raise Failure('portal_environment_unresolved')
    parameters = SimpleNamespace(project=config['project_uuid'], environment=matches[0]['uuid'],
        destination=portal['destination']['uuid'], server=config['server_uuid'])
    context = scope.portal_context(api, portal, parameters)
    raw = Path(__file__).with_name('compose.backup-sealer.yml').read_text()
    substitutions = {'BACKUP_SEAL_IMAGE': 'git.cl8y.com/code/cl8y-wallet-security-backup-seal@' + config['sealer_image_manifest'],
        'AGE_PUBLIC_RECIPIENT': config['age_public_recipient'], 'PORTAL_BACKUP_VOLUME': config['input_backup_volume'],
        'SEALED_BACKUP_VOLUME': config['sealed_backup_volume']}
    for key, value in substitutions.items(): raw = raw.replace('${' + key + ':?}', value)
    desired = yaml.safe_load(raw); service = api.call('GET', '/services/' + config['sealer_uuid'])
    scope.validate_resource(service, config['sealer_uuid'], config['sealer_name'], desired, context, parameters)
    if args.observed_image_manifest != config['sealer_image_manifest']:
        raise Failure('daemon_image_binding_differs')
    storages = api.call('GET', '/services/' + config['sealer_uuid'] + '/storages')
    outputs = [item for item in storages.get('persistent_storages', []) if item.get('mount_path') == '/encrypted']
    if len(outputs) != 1 or outputs[0].get('name') != args.observed_output_volume or outputs[0].get('host_path'):
        raise Failure('native_metadata_and_daemon_volume_differ')
    if args.observed_output_volume != config['sealer_uuid'] + '_sealed':
        raise Failure('resolved_output_outside_owned_service_namespace')
    config.update(resource_context=context, environment_uuid=parameters.environment,
        destination_uuid=parameters.destination,
        desired_compose_sha256=hashlib.sha256(json.dumps(desired, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        resolved_sealed_volume=args.observed_output_volume, output_storage_uuid=outputs[0]['uuid'],
        daemon_binding_verified=True, daemon_observer_job='jjgal8ol8wrtisfy4daoxngf')
    write_private(path, config)
    print(json.dumps({'prepared_metadata_only': True, 'actual_image_and_volume_bound': True,
        'registered_host_path_empty': True, 'producer_or_portal_mutated': False}))


if __name__ == '__main__': safe_main(main)
