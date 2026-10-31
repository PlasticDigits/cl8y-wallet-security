import base64
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backup_control import Api, Failure
spec = importlib.util.spec_from_file_location('provision_sealer', ROOT / 'provision-backup-sealer.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
APP, PROJECT, ENV, SERVER, DEST, SERVICE = (c * 24 for c in 'pjvsdx')


class FakeApi:
    def __init__(self):
        self.started = False
        self.created = False
        self.recover = False
        self.drift = None
        self.environment_id = 7
        self.compose = None

    def service(self):
        value = {'uuid': SERVICE, 'name': 'cl8y-wallet-security-backup-sealer-' + APP[:8],
                 'environment_id': 7, 'destination_id': 3, 'server_id': 5,
                 'destination': {'uuid': DEST, 'server': {'uuid': SERVER}},
                 'docker_compose_raw': yaml.safe_dump(self.compose)}
        if self.drift:
            self.drift(value)
        return value

    def call(self, method, path, data=None):
        if path == '/applications/' + APP:
            return {'uuid': APP, 'name': 'cl8y-wallet-security', 'environment_id': self.environment_id,
                    'destination_id': 3, 'destination': {'uuid': DEST, 'id': 3, 'server_id': 5,
                    'server': {'uuid': SERVER, 'id': 5}}}
        if path == '/projects/' + PROJECT:
            return {'uuid': PROJECT, 'environments': [{'uuid': ENV, 'id': 7}]}
        if path.endswith('/storages'):
            return {'persistent_storages': [{'name': APP + '_backups', 'mount_path': '/backups'}]}
        if path == '/services' and method == 'GET':
            return [{'uuid': SERVICE, 'name': 'cl8y-wallet-security-backup-sealer-' + APP[:8]}] if self.recover else []
        if path == '/services' and method == 'POST':
            self.created = True
            self.compose = yaml.safe_load(base64.b64decode(data['docker_compose_raw']))
            return {'uuid': SERVICE}
        if path == '/services/' + SERVICE:
            return self.service()
        if path == '/services/' + SERVICE + '/start':
            self.started = True
            return {}
        raise AssertionError('unexpected API operation')


class ProvisionGuards(unittest.TestCase):
    def invoke(self, fake, branch='new'):
        with tempfile.TemporaryDirectory() as directory:
            config, custody = Path(directory) / 'state.json', Path(directory) / 'custody.json'
            custody.write_text(json.dumps({'age_public_recipient': 'age1fixture'}))
            # Establish desired compose for reuse tests without a real API/create.
            source = (ROOT / 'compose.backup-sealer.yml').read_text()
            values = {'BACKUP_SEAL_IMAGE': 'git.cl8y.com/code/cl8y-wallet-security-backup-seal@sha256:' + 'd' * 64,
                      'AGE_PUBLIC_RECIPIENT': 'age1fixture', 'PORTAL_BACKUP_VOLUME': APP + '_backups',
                      'SEALED_BACKUP_VOLUME': APP + '_sealed_backups'}
            for key, value in values.items(): source = source.replace('${' + key + ':?}', value)
            fake.compose = yaml.safe_load(source)
            if branch == 'cached': config.write_text(json.dumps({'sealer_uuid': SERVICE}))
            if branch == 'recover': fake.recover = True
            argv = ['provision', '--config', str(config), '--portal-app', APP, '--project', PROJECT,
                    '--environment', ENV, '--server', SERVER, '--destination', DEST,
                    '--image-digest', 'sha256:' + 'd' * 64, '--image-source', 'a' * 40,
                    '--custody-metadata', str(custody)]
            with patch.object(sys, 'argv', argv), patch.object(module, 'Api', return_value=fake), patch('builtins.print'):
                module.main()

    def test_valid_new_create_readback_then_start(self):
        fake = FakeApi(); self.invoke(fake)
        self.assertTrue(fake.created and fake.started)

    def test_wrong_portal_context_fails_before_create(self):
        fake = FakeApi(); fake.environment_id = 99
        with self.assertRaises(Failure): self.invoke(fake)
        self.assertFalse(fake.created or fake.started)

    def test_all_reuse_and_postcreate_paths_reject_resource_drift(self):
        def compose_drift(key, value):
            def change(resource):
                parsed = yaml.safe_load(resource['docker_compose_raw'])
                parsed['services']['seal'][key] = value
                resource['docker_compose_raw'] = yaml.safe_dump(parsed)
            return change
        changes = [compose_drift('image', 'wrong/image'), compose_drift('user', '0'),
                   compose_drift('network_mode', 'host'), compose_drift('volumes', []),
                   compose_drift('environment', {'AGE_PUBLIC_RECIPIENT': 'age1wrong'}),
                   compose_drift('privileged', True),
                   lambda resource: resource.update(server_id=999)]
        for branch in ['new', 'cached', 'recover']:
            for change in changes:
                with self.subTest(branch=branch, change=changes.index(change)):
                    fake = FakeApi(); fake.drift = change
                    with self.assertRaises(Failure): self.invoke(fake, branch)
                    self.assertFalse(fake.started)

    def test_cached_and_recovered_valid_resources_start_without_create(self):
        for branch in ['cached', 'recover']:
            fake = FakeApi(); self.invoke(fake, branch)
            self.assertTrue(fake.started)
            self.assertFalse(fake.created)


class BoundedReads(unittest.TestCase):
    def test_success_body_is_bounded_and_rejected(self):
        class Response:
            calls = []
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, count): self.calls.append(count); return b'x' * count
        response = Response()
        api = Api.__new__(Api); api.base = 'https://fixture.invalid'; api.headers = {}
        api.opener = type('Opener', (), {'open': lambda *_args, **_kwargs: response})()
        with self.assertRaisesRegex(Failure, 'response_too_large'): api.call('GET', '/fixture')
        self.assertEqual(response.calls, [Api.MAX_RESPONSE_BYTES + 1])

    def test_error_body_is_bounded(self):
        body = io.BytesIO(b'x' * (Api.MAX_RESPONSE_BYTES + 100))
        error = urllib.error.HTTPError('https://fixture.invalid', 500, 'fixed', {}, body)
        api = Api.__new__(Api); api.base = 'https://fixture.invalid'; api.headers = {}
        class Opener:
            def open(self, *_args, **_kwargs): raise error
        api.opener = Opener()
        with self.assertRaisesRegex(Failure, 'http_500'): api.call('GET', '/fixture')
        self.assertEqual(body.tell(), Api.MAX_RESPONSE_BYTES + 1)


if __name__ == '__main__': unittest.main()
