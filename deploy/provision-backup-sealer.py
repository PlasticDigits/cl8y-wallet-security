#!/usr/bin/env python3
"""Provision only a separate no-network public-key backup sealer resource."""
import argparse
import base64
import json
import re
from pathlib import Path
import yaml
from backup_control import Api, Failure, identifier, safe_main, write_private


def portal_context(api, portal, args):
    project = api.call('GET', '/projects/' + args.project)
    environments = [item for item in project.get('environments', []) if item.get('uuid') == args.environment]
    destination = portal.get('destination') or {}
    server = destination.get('server') or {}
    if (project.get('uuid') != args.project or len(environments) != 1
            or environments[0].get('id') is None
            or portal.get('environment_id') != environments[0]['id']
            or destination.get('uuid') != args.destination
            or portal.get('destination_id') != destination.get('id')
            or destination.get('id') is None or server.get('id') is None
            or destination.get('server_id') != server['id']
            or server.get('uuid') != args.server):
        raise Failure('portal_project_environment_server_context_differs')
    return {'environment_id': environments[0]['id'], 'destination_id': destination['id'], 'server_id': server['id']}


def validate_resource(resource, expected_uuid, expected_name, expected_compose, context, args):
    destination = resource.get('destination') or {}
    server = destination.get('server') or {}
    if (resource.get('uuid') != expected_uuid or resource.get('name') != expected_name
            or any(resource.get(key) != value for key, value in context.items())
            or destination.get('uuid') != args.destination or server.get('uuid') != args.server):
        raise Failure('sealer_actual_resource_context_differs')
    actual = yaml.safe_load(resource.get('docker_compose_raw') or '')
    # Compare the complete resolved declaration, including recipient, both
    # owned mounts, no extra services/env/ports/network/privilege, and limits.
    if actual != expected_compose:
        raise Failure('sealer_actual_resolved_compose_differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--portal-app', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--environment', required=True)
    parser.add_argument('--server', required=True)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--image-digest', required=True)
    parser.add_argument('--image-source', required=True)
    parser.add_argument('--custody-metadata', required=True)
    args = parser.parse_args()
    for field in ['portal_app', 'project', 'environment', 'server', 'destination']:
        identifier(getattr(args, field))
    if not re.fullmatch('sha256:[0-9a-f]{64}', args.image_digest) or not re.fullmatch('[0-9a-f]{40}', args.image_source):
        raise Failure('invalid_sealer_artifact_identity')
    api = Api()
    portal = api.call('GET', '/applications/' + args.portal_app)
    if portal.get('uuid') != args.portal_app or portal.get('name') != 'cl8y-wallet-security':
        raise Failure('not_owned_portal')
    context = portal_context(api, portal, args)
    input_volume = args.portal_app + '_backups'
    storages = api.call('GET', '/applications/' + args.portal_app + '/storages')
    if not any(item.get('name') == input_volume and item.get('mount_path') == '/backups' for item in storages.get('persistent_storages', [])):
        raise Failure('owned_input_backup_volume_not_registered')
    metadata = json.loads(Path(args.custody_metadata).read_text())
    recipient = metadata.get('age_public_recipient') or ''
    if not re.fullmatch('age1[0-9a-z]+', recipient):
        raise Failure('invalid_public_encryption_recipient')
    output_volume = args.portal_app + '_sealed_backups'
    image = 'git.cl8y.com/code/cl8y-wallet-security-backup-seal@' + args.image_digest
    source = Path(__file__).with_name('compose.backup-sealer.yml').read_text()
    substitutions = {'BACKUP_SEAL_IMAGE': image, 'AGE_PUBLIC_RECIPIENT': recipient,
                     'PORTAL_BACKUP_VOLUME': input_volume, 'SEALED_BACKUP_VOLUME': output_volume}
    for key, value in substitutions.items():
        source = source.replace('${' + key + ':?}', value)
    compose = yaml.safe_load(source)
    service = compose['services']['seal']
    if service['network_mode'] != 'none' or service['user'] != '999:999' or not service['read_only']:
        raise Failure('sealer_boundary_changed')
    config_path = Path(args.config)
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    expected_name = 'cl8y-wallet-security-backup-sealer-' + args.portal_app[:8]
    if not config.get('sealer_uuid'):
        # Resolve an earlier unknown create outcome before requesting a new one.
        matches = [item for item in api.call('GET', '/services') if item.get('name') == expected_name]
        if len(matches) > 1:
            raise Failure('ambiguous_existing_sealer_resource')
        if matches:
            config['sealer_uuid'] = identifier(matches[0]['uuid'])
        else:
        # API service creation has no Git helper/build step or runtime secret file.
            resource = api.call('POST', '/services', {'name': expected_name,
                'project_uuid': args.project, 'environment_uuid': args.environment,
                'server_uuid': args.server, 'destination_uuid': args.destination,
                'docker_compose_raw': base64.b64encode(source.encode()).decode(), 'instant_deploy': False})
            config['sealer_uuid'] = identifier(resource['uuid'])
        # Retain the identifier even if post-create readback fails; never
        # blindly repeat a possibly successful create on a retry.
        write_private(config_path, config)
    actual = api.call('GET', '/services/' + identifier(config['sealer_uuid']))
    # One guard serves cached IDs, name-recovery and fresh-create readback.
    # Nothing can POST /start before complete actual validation passes.
    validate_resource(actual, config['sealer_uuid'], expected_name, compose, context, args)
    config.update(portal_app_uuid=args.portal_app, project_uuid=args.project, server_uuid=args.server,
                  sealer_source_sha=args.image_source, sealer_image_manifest=args.image_digest,
                  input_backup_volume=input_volume, sealed_backup_volume=output_volume,
                  age_public_recipient=recipient, sealer_name=expected_name,
                  custody_name='wallet-security/recovery', max_source_age_seconds=90000,
                  offhost_expiration_days=4)
    write_private(config_path, config)
    api.call('POST', '/services/' + config['sealer_uuid'] + '/start')
    print(json.dumps({'sealer_uuid': config['sealer_uuid'], 'source_sha': args.image_source,
                      'image_manifest_digest': args.image_digest, 'public_recipient_only': True,
                      'new_sealer_start_requested': True, 'portal_resource_changed': False}))


if __name__ == '__main__':
    safe_main(main)
