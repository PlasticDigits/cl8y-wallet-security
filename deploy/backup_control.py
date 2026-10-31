"""Operator-only backup API helpers. Never serialize credentials or API bodies."""
import datetime
import json
import logging
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

logging.disable(logging.CRITICAL)


class Failure(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Api:
    MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    def __init__(self):
        origin = os.environ['COOLIFY_URL'].rstrip('/')
        parsed = urllib.parse.urlsplit(origin)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise Failure('invalid_control_plane_origin')
        self.base = origin + '/api/v1'
        self.headers = {'Authorization': 'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'],
                        'Content-Type': 'application/json', 'Accept': 'application/json'}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, path, data=None):
        request = urllib.request.Request(self.base + path, method=method, headers=self.headers,
            data=None if data is None else json.dumps(data).encode())
        try:
            with self.opener.open(request, timeout=35) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
                if len(raw) > self.MAX_RESPONSE_BYTES:
                    raise Failure('control_plane_response_too_large')
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as error:
            error.read(self.MAX_RESPONSE_BYTES + 1)
            raise Failure('control_plane_http_' + str(error.code)) from None


def identifier(value):
    if not re.fullmatch('[a-z0-9]{20,32}', value or ''):
        raise Failure('invalid_resource_identifier')
    return value


def write_private(path, data):
    os.umask(0o077)
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.new')
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


def s3_client(storage):
    # Explicit in-memory credentials bypass all ambient SDK credential providers.
    # No AWS config/credential file is created; this code never runs in a workload.
    import boto3
    from botocore.config import Config
    parsed = urllib.parse.urlsplit(storage.get('endpoint') or '')
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise Failure('invalid_offhost_endpoint')
    if not storage.get('key') or not storage.get('secret'):
        raise Failure('platform_storage_credential_unavailable')
    return boto3.client('s3', endpoint_url=storage['endpoint'], region_name=storage['region'],
        aws_access_key_id=storage['key'], aws_secret_access_key=storage['secret'],
        config=Config(signature_version='s3v4', connect_timeout=10, read_timeout=30,
                      retries={'total_max_attempts': 1}, proxies={},
                      s3={'addressing_style': 'path' if storage.get('use_path_style_endpoint', True) else 'virtual'}))


def s3_error_code(error):
    code = getattr(error, 'response', {}).get('Error', {}).get('Code')
    allowed = {'404', '403', 'NoSuchBucket', 'NoSuchKey', 'AccessDenied', 'NoSuchLifecycleConfiguration',
               'BucketAlreadyOwnedByYou', 'BucketAlreadyExists', 'SignatureDoesNotMatch', 'InvalidLocationConstraint'}
    return code if code in allowed else 'storage_request_failed'


def safe_main(function):
    try:
        function()
    except Failure as error:
        raise SystemExit('backup_operation_failed ' + str(error)) from None
    except Exception as error:
        # Never interpolate exception bodies/SDK responses: they may echo material.
        raise SystemExit('backup_operation_failed ' + type(error).__name__) from None


def validate_sealer(api, config):
    import hashlib
    import yaml
    portal = api.call('GET', '/applications/' + identifier(config['portal_app_uuid']))
    if portal.get('name') != 'cl8y-wallet-security':
        raise Failure('portal_identity_changed')
    service = api.call('GET', '/services/' + identifier(config['sealer_uuid']))
    destination = service.get('destination') or {}
    server = destination.get('server') or {}
    if (service.get('name') != config['sealer_name']
            or any(service.get(key) != value for key, value in config['resource_context'].items())
            or destination.get('uuid') != config['destination_uuid']
            or server.get('uuid') != config['server_uuid']):
        raise Failure('sealer_resource_context_changed')
    compose = yaml.safe_load(service.get('docker_compose_raw') or '')
    digest = hashlib.sha256(json.dumps(compose, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if digest != config['desired_compose_sha256']:
        raise Failure('sealer_actual_compose_changed')
    return service
