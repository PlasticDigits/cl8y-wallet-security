import copy
import datetime as dt
import hashlib
import importlib.util
import io
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
        with patch.object(capture,'observe',return_value={'fixture_daemon_observed':True}),patch.object(capture.secrets,'token_hex',side_effect=lambda n:'b'*(n*2)),patch.object(capture.socket,'create_connection',side_effect=ConnectionRefusedError),patch.object(capture.urllib.request,'build_opener',return_value=opener):
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
        with patch.object(capture,'observe',return_value={'fixture_daemon_observed':True}),patch.object(capture.socket,'create_connection',side_effect=ConnectionRefusedError),patch.object(capture.urllib.request,'build_opener',return_value=Opener()):
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
class NoBucketPolicy(Exception):
    response={'Error':{'Code':'NoSuchBucketPolicy'}}
class S3Fixture:
    def __init__(self,exists=False,version=None):self.exists=exists;self.version=version;self.writes=[]
    def head_bucket(self,**_):
        if not self.exists:raise MissingBucket()
    def create_bucket(self,**kwargs):self.writes.append(('create',kwargs));self.exists=True
    def get_bucket_acl(self,**_):return {'Owner':{'ID':'owned-account'},'Grants':[{'Grantee':{'Type':'CanonicalUser','ID':'owned-account'},'Permission':'FULL_CONTROL'}]}
    def get_bucket_policy(self,**_):raise NoBucketPolicy()
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

class FinalControllerNegatives(unittest.TestCase):
    def test_cloned_config_cannot_reuse_persisted_claim(self):
        cfg={'lease_owner':'old-shared-owner','resolved_sealed_volume':'owned'}
        with patch.object(capture.secrets,'token_hex',side_effect=['first-fresh','second-fresh']):
            first=capture.new_claim(copy.deepcopy(cfg));second=capture.new_claim(copy.deepcopy(cfg))
        self.assertNotEqual(first,second)
        client=type('Client',(),{'request':lambda *_args,**_kwargs:self.fail('second actor wrote active lease')})()
        current={'owner':first,'volume':'owned','expires':str(int(time.time())+100)}
        with patch.object(capture,'optional_kv',return_value=(current,{'version':1})):
            with self.assertRaises(Failure):capture.lease(client,'entity',cfg,second)
    def test_expired_or_foreign_claim_cannot_renew_or_release(self):
        writes=[];client=type('Client',(),{'request':lambda *_args,**_kwargs:writes.append(True)})()
        cfg={'resolved_sealed_volume':'owned'}
        with patch.object(capture,'optional_kv',return_value=({'owner':'mine','volume':'owned','expires':'0'},{'version':1})):
            with self.assertRaises(Failure):capture.lease(client,'entity',cfg,'mine',renew=True)
        with patch.object(capture,'optional_kv',return_value=({'owner':'new-generation','volume':'owned','expires':str(int(time.time())+100)},{'version':2})):
            capture.lease(client,'entity',cfg,'old-generation',release=True)
        self.assertEqual(writes,[])
    def test_model404_does_not_drop_unproven_listener_state(self):
        cfg={'active_export':{'uuid':ID,'name':'owned','compose':{}}}
        class Gone:
            def call(self,*_args,**_kwargs):raise Failure('control_plane_http_404')
        with patch.object(capture,'wait_private_closed',side_effect=Failure('listener_still_present')):
            with self.assertRaises(Failure):capture.cleanup_export(Gone(),cfg,lambda:None)
        self.assertIn('active_export',cfg)
    def test_tag_and_size_filtered_expiry_are_not_catchall(self):
        from backup_control import validate_lifecycle
        base={'ID':'wallet-security-four-day-expiry','Status':'Enabled','Expiration':{'Days':4},'AbortIncompleteMultipartUpload':{'DaysAfterInitiation':1}}
        for bad in [{'Tag':{'Key':'inapplicable','Value':'true'}},{'And':{'Prefix':'','Tags':[]}},{'ObjectSizeGreaterThan':100}]:
            with self.assertRaises(Failure):validate_lifecycle({'Rules':[{**base,'Filter':bad}]})
        validate_lifecycle({'Rules':[{**base,'Prefix':''}]})
        validate_lifecycle({'Rules':[{**base,'Filter':{'Prefix':''}}]})
    def test_actual_runtime_observer_rejects_public_or_extra_scope(self):
        from export_observation import verify_records
        cfg={'export_image':'fixture@sha256:'+'d'*64,'export_source_sha':'a'*40,'resolved_sealed_volume':'owned'}
        records='\n'.join(['WG_OBS_IMAGE reference=sha256:'+'d'*64+' source='+'a'*40,
            'WG_OBS_HOST user=999:999 running=true network=host memory=67108864 cpu=100000000 pids=16 readonly=true ports=0',
            'WG_OBS_MOUNT volume owned /export false','WG_OBS_CAPDROP ALL','WG_OBS_SECURITY no-new-privileges:true',
            'WG_OBS_ENV_NAMES_BEGIN','PATH','EXPORT_TOKEN','EXPECTED_CIPHER_SHA256','EXPORT_FILENAME','EXPORT_EXPIRES_UNIX','WG_OBS_ENV_NAMES_END',
            'WG_OBS_LISTEN 0100080A:470C','WG_OBS_COMPLETE read_only=true'])
        self.assertTrue(verify_records(records,cfg)['private_listener_only_verified'])
        for mutated in [records.replace('0100080A:470C','00000000:470C'),records+'\nWG_OBS_MOUNT volume foreign /root true',records.replace('PATH\n','PATH\nCOOLIFY_TOKEN\n')]:
            with self.assertRaises(Failure):verify_records(mutated,cfg)

class TaskAndFenceOutcomes(unittest.TestCase):
    def test_execute_response_error_is_reconciled_before_task_deletion(self):
        now=dt.datetime.now(dt.timezone.utc).isoformat();events=[]
        class Api:
            def call(self,method,path,data=None):
                events.append((method,path))
                if method=='GET' and path.endswith('/scheduled-tasks'):return []
                if method=='POST' and path.endswith('/scheduled-tasks'):return {'uuid':ID}
                if path.endswith('/execute'):raise Failure('control_plane_http_500')
                if path.endswith('/executions'):return [{'status':'success','created_at':now,'message':'owned-done'}]
                if method=='DELETE':return {}
                raise AssertionError('unexpected')
        self.assertEqual(capture.task(Api(),'s'*24,'owned','fixed-command',1),'owned-done')
        self.assertEqual(events[-1][0],'DELETE')
    def test_unknown_execute_outcome_keeps_task_for_reconciliation(self):
        events=[]
        class Api:
            def call(self,method,path,data=None):
                events.append((method,path))
                if method=='GET':return []
                if path.endswith('/scheduled-tasks'):return {'uuid':ID}
                raise Failure('control_plane_http_500')
        with self.assertRaises(capture.UnknownTask):capture.task(Api(),'s'*24,'owned','fixed-command',0)
        self.assertFalse(any(method=='DELETE' for method,_ in events))
    def test_cleanup_failure_keeps_producer_fenced_and_claim_unreleased(self):
        cfg={'resolved_sealed_volume':'owned','sealer_uuid':'s'*24,'daemon_binding_verified':True,
            'inspector_app_uuid':'i'*24,'inspector_source_sha':'a'*40,'inspector_name':'owned-inspector',
            'export_image':'fixture','export_source_sha':'a'*40}
        stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        ready='sealed_backup_ready dump=wallet-security-'+stamp+'.dump cipher_sha256='+'d'*64
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'cfg.json';path.write_text(json.dumps(cfg));claims=[];commands=[]
            def fake_task(_api,_service,_name,command,*_args,**_kwargs):commands.append(command);return ready
            def broken_fetch(_api,config,*_args,**_kwargs):config['active_export']={'uuid':ID};raise Failure('cleanup_unconfirmed')
            health=io.BytesIO(json.dumps({'source_sha':'a'*40,'migration':5}).encode())
            with patch.object(sys,'argv',['capture','--config',str(path),'--expected-source','a'*40,'--expected-migration','5','--probe-only']),patch.object(capture,'Api'),patch.object(capture,'validate_sealer'),patch.object(capture,'vault',return_value=(object(),'entity')),patch.object(capture,'lease',side_effect=lambda *a,**k:claims.append(k)),patch.object(capture,'cleanup_export'),patch.object(capture,'task',side_effect=fake_task),patch.object(capture,'fetch_cipher',side_effect=broken_fetch),patch.object(capture.urllib.request,'urlopen',return_value=health):
                with self.assertRaisesRegex(Failure,'cleanup_unconfirmed'):capture.main()
            self.assertEqual(commands,['/bin/bash /app/seal-backup.sh pause'])
            self.assertFalse(any(call.get('release') for call in claims))
