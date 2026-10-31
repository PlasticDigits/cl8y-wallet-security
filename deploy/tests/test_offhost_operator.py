import copy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backup_control import Failure

def load(name, path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
capture=load('capture_test','backup-capture.py')
enroll=load('enroll_test','enroll-offhost-storage.py')
ID='x'*24

class OwnedApi:
    def __init__(self,cfg):self.cfg=cfg;self.compose=None;self.name=None;self.deleted=False;self.events=[]
    def call(self,method,path,data=None):
        self.events.append((method,path))
        if method=='POST' and path=='/services':
            import base64
            self.compose=yaml.safe_load(base64.b64decode(data['docker_compose_raw']));self.name=data['name'];return {'uuid':ID}
        if method=='GET' and path=='/services/'+ID:
            if self.deleted:raise Failure('control_plane_http_404')
            return {'uuid':ID,'name':self.name,**self.cfg['resource_context'],'destination':{'uuid':self.cfg['destination_uuid'],'server':{'uuid':self.cfg['server_uuid']}},'docker_compose_raw':yaml.safe_dump(self.compose)}
        if method=='PATCH' and path.endswith('/envs'):
            self.env=data;return {}
        if method=='POST' and (path.endswith('/start') or path.endswith('/stop')):return {}
        if method=='DELETE' and path.startswith('/services/'+ID+'?'):
            self.assert_cleanup_flags='delete_volumes=false' in path and 'delete_connected_networks=false' in path and 'docker_cleanup=false' in path
            self.deleted=True;return {}
        raise AssertionError('unexpected scoped operation')

class CipherResponse:
    status=200
    def __init__(self,body):self.body=body;self.headers={'Content-Length':str(len(body))}
    def __enter__(self):return self
    def __exit__(self,*_):pass
    def read(self,limit):return self.body[:limit]

class CaptureBoundaries(unittest.TestCase):
    def cfg(self):return {'project_uuid':'p'*24,'environment_uuid':'v'*24,'server_uuid':'s'*24,'destination_uuid':'d'*24,'resource_context':{'environment_id':0,'server_id':0,'destination_id':0},'resolved_sealed_volume':'owned_sealed','export_image':'fixture/export@sha256:'+'d'*64}
    def test_capture_keeps_capability_out_of_raw_config_and_cleans_after_hash(self):
        data=b'age-encryption.org/v1\nowned-cipher-fixture';cfg=self.cfg();api=OwnedApi(cfg);persisted=[]
        record={'dump':'wallet-security-20261031T000000Z.dump','cipher_sha256':hashlib.sha256(data).hexdigest()}
        class Opener:
            def open(self,request,**_):
                self.last=request;return CipherResponse(data)
        opener=Opener()
        with patch.object(capture.secrets,'token_hex',side_effect=lambda n:'b'*(n*2)),patch.object(capture.socket,'create_connection',side_effect=ConnectionRefusedError),patch.object(capture.urllib.request,'build_opener',return_value=opener):
            out=capture.fetch_cipher(api,cfg,record,lambda:persisted.append(copy.deepcopy(cfg)))
        self.assertEqual(out,data);self.assertTrue(api.deleted and api.assert_cleanup_flags)
        self.assertNotIn('b'*64,json.dumps(persisted));self.assertNotIn('b'*64,json.dumps(api.compose))
        self.assertEqual(api.env['key'],'EXPORT_TOKEN');self.assertTrue(api.env['is_shown_once'])
        self.assertNotIn('active_export',cfg);self.assertEqual(opener.last.full_url,'http://10.8.0.1:18188/cipher')
    def test_bad_whole_cipher_hash_never_returns_and_still_cleans(self):
        data=b'age-encryption.org/v1\nowned-corrupt-cipher';cfg=self.cfg();api=OwnedApi(cfg)
        record={'dump':'wallet-security-20261031T000000Z.dump','cipher_sha256':'a'*64}
        class Opener:
            def open(self,*_args,**_):return CipherResponse(data)
        with patch.object(capture.socket,'create_connection',side_effect=ConnectionRefusedError),patch.object(capture.urllib.request,'build_opener',return_value=Opener()):
            with self.assertRaisesRegex(Failure,'whole_cipher_hash'):capture.fetch_cipher(api,cfg,record,lambda:None)
        self.assertTrue(api.deleted)
    def test_occupied_private_port_never_creates_or_stops_resource(self):
        class Existing:
            def __enter__(self):return self
            def __exit__(self,*_):pass
        cfg=self.cfg();api=OwnedApi(cfg)
        with patch.object(capture.socket,'create_connection',return_value=Existing()):
            with self.assertRaisesRegex(Failure,'already_in_use'):capture.fetch_cipher(api,cfg,{},lambda:None)
        self.assertEqual(api.events,[])
    def test_ready_record_requires_anchored_fresh_completed_pair(self):
        stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ');line='sealed_backup_ready dump=wallet-security-'+stamp+'.dump cipher_sha256='+'a'*64
        self.assertEqual(capture.ready_record(line)['stamp'],stamp)
        with self.assertRaises(Failure):capture.ready_record('Command failed: '+line)
        with self.assertRaises(Failure):capture.ready_record(line.replace(stamp,'20000101T000000Z'))
    def test_lease_rejects_second_actor_and_foreign_volume(self):
        class Client:
            def __init__(self):self.wrote=False
            def request(self,*_):self.wrote=True
        client=Client();cfg={'resolved_sealed_volume':'owned'}
        with patch.object(capture,'optional_kv',return_value=({'owner':'other','volume':'owned','expires':str(int(time.time())+100)},{'version':1})):
            with self.assertRaises(Failure):capture.lease(client,'entity',cfg,'mine')
        self.assertFalse(client.wrote)
        with patch.object(capture,'optional_kv',return_value=({'owner':'mine','volume':'foreign','expires':'0'},{'version':1})):
            with self.assertRaises(Failure):capture.lease(client,'entity',cfg,'mine')

class MissingBucket(Exception):
    response={'Error':{'Code':'NoSuchBucket'}}
class S3Fixture:
    def __init__(self,exists=False,version=None):self.exists=exists;self.version=version;self.writes=[]
    def head_bucket(self,**_):
        if not self.exists:raise MissingBucket()
    def create_bucket(self,**kwargs):self.writes.append(('create',kwargs));self.exists=True
    def get_bucket_acl(self,**_):return {'Owner':{'ID':'owned-account'},'Grants':[{'Grantee':{'Type':'CanonicalUser','ID':'owned-account'},'Permission':'FULL_CONTROL'}]}
    def get_bucket_versioning(self,**_):return {'Status':self.version} if self.version else {}
    def put_bucket_lifecycle_configuration(self,**kwargs):self.writes.append(('lifecycle',kwargs));self.life=kwargs['LifecycleConfiguration']
    def get_bucket_lifecycle_configuration(self,**_):return self.life
    def put_object(self,**kwargs):self.writes.append(('marker',kwargs));return {}
class EnrollScope(unittest.TestCase):
    def invoke(self,s3,known=False):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'metadata.json';cfg={'portal_app_uuid':'p'*24,'sealer_uuid':'s'*24}
            if known:cfg['bucket_created_by_this_operator']=True
            path.write_text(json.dumps(cfg))
            class Api:
                def call(self,method,*_args,**_):
                    if method!='GET':raise AssertionError('must not invoke native credentials or mutate platform')
                    return {'uuid':'z'*24,'is_usable':True}
            argv=['enroll','--config',str(path),'--source-storage','z'*24]
            with patch.object(sys,'argv',argv),patch.object(enroll,'Api',return_value=Api()),patch.object(enroll,'validate_sealer'),patch.object(enroll,'s3_client',return_value=s3),patch('builtins.print'):
                enroll.main()
            return json.loads(path.read_text())
    def test_new_bucket_scope_four_day_readback_no_platform_mutation(self):
        s3=S3Fixture();cfg=self.invoke(s3)
        self.assertTrue(cfg['lifecycle_verified']);self.assertFalse(cfg['versioning_enabled'])
        self.assertEqual({item[1]['Bucket'] for item in s3.writes},{'cl8y-wallet-security-'+'p'*12+'-encrypted'})
        self.assertEqual(s3.life['Rules'][0]['Expiration']['Days'],4)
        self.assertEqual(s3.life['Rules'][0]['AbortIncompleteMultipartUpload']['DaysAfterInitiation'],1)
    def test_unknown_existing_bucket_has_no_mutations(self):
        s3=S3Fixture(exists=True)
        with self.assertRaisesRegex(Failure,'not_proven_owned'):self.invoke(s3)
        self.assertEqual(s3.writes,[])
    def test_versioned_known_bucket_rejected_before_lifecycle(self):
        s3=S3Fixture(exists=True,version='Enabled')
        with self.assertRaisesRegex(Failure,'never_versioned'):self.invoke(s3,known=True)
        self.assertEqual(s3.writes,[])

if __name__=='__main__':unittest.main()
