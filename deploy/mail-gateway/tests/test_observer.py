import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('gateway',ROOT/'provision.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
FAKE=r'''#!/usr/bin/env python3
import sys,os
from pathlib import Path
a=sys.argv[1:]
if not (a[0]=='inspect' or a[:2] in [['network','inspect'],['network','ls']] or a[0]=='events'):
 Path(os.environ['OBSERVER_MUTATION_MARKER']).write_text('unexpected mutation');raise SystemExit(1)
if a[0]=='events':
 print('connect|'+'b'*64+'|wallet-security-notification|'+'f'*64+'|1234');raise SystemExit(0)
if a[:2]==['network','ls']:print('b'*64);raise SystemExit(0)
f=a[a.index('-f')+1];name=a[-1]
if a[:2]==['network','inspect']:
 if name.startswith('y08'):raise SystemExit(1)
 if '.Name' in f and '.Containers' not in f:print('wallet-security-notification')
 elif '.Driver' in f:print('bridge')
 elif '.Internal' in f:print('true')
 elif 'len .Containers' in f:print('4')
 elif '.Containers' in f:
  print('a'*64+'|wallet-security-mail-gateway')
  print('d'*64+'|seal-3nolvrgyhudkv3itihuyuim9')
  print('c'*64+'|coolify-proxy')
  print('f'*64+'|unrelated-private-service')
 else:print('b'*64)
 raise SystemExit(0)
sealer=name.startswith('seal-')
if '.Config.Env' in f:
 assert 'split . "="' in f and 'index' in f
 print('PATH\nSEALER_KEY' if sealer else 'PATH');raise SystemExit(0)
if f=='{{.Id}}':print(('d' if sealer else 'a')*64)
elif f=='{{.Image}}':print('sha256:'+('f'*64 if sealer else 'e'*64))
elif 'com.cl8y.scope' in f:print('wallet-security-mail-gateway')
elif 'org.opencontainers.image.revision' in f:print('44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5')
elif '.Config.User' in f:print('10001:10001')
elif '.State.Running' in f:print('false')
elif '.NetworkMode' in f:print('none' if sealer else 'wallet-security-notification')
elif '.Memory' in f:print('67108864')
elif '.NanoCpus' in f:print('100000000')
elif '.PidsLimit' in f:print('16')
elif '.ReadonlyRootfs' in f:print('true')
elif '.CapDrop' in f:print('ALL')
elif '.SecurityOpt' in f:print('no-new-privileges:true')
elif 'len .Mounts' in f:print('1' if sealer else '0')
elif '.Mounts' in f:
 if sealer:print('volume|3nolvrgyhudkv3itihuyuim9_sealed|/sealed|true')
elif '.NetworkSettings.Networks' in f:print('wallet-security-notification|'+'b'*64+'|mail.cl8y.com,gateway')
else:raise SystemExit(1)
'''
class Observer(unittest.TestCase):
 def test_two_targets_metadata_only_and_intentional_stop(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);binary=root/'docker';binary.write_text(FAKE);binary.chmod(0o700)
   marker=root/'mutation'
   env=os.environ.copy();env.update(PATH=str(root)+':'+env['PATH'],OBSERVER_MUTATION_MARKER=str(marker))
   r=subprocess.run(['bash',str(ROOT/'observe.sh')],env=env,capture_output=True,text=True,timeout=5)
   self.assertEqual(r.returncode,1)
   self.assertIn('observer_read_only_complete_service_changes=false',r.stdout)
   self.assertIn('"role":"sealer"',r.stdout)
   self.assertIn('3nolvrgyhudkv3itihuyuim9_sealed',r.stdout)
   self.assertNotIn('Env=',r.stdout)
   self.assertNotIn('unrelated-private-service',r.stdout)
   rows=[json.loads(line) for line in r.stdout.splitlines() if line.startswith('{')]
   self.assertTrue(any(x.get('record')=='network_redacted_members' and x['other_members']==1 for x in rows))
   self.assertTrue(any(x.get('record')=='owned_network_event' and x['container_id']=='' and x['container_kind']=='other_redacted' for x in rows))
   self.assertFalse(marker.exists())
   for line in r.stdout.splitlines():
    if line.startswith('{'):self.assertTrue(m.observer_record(line),line)
 def test_live_capture_only_gateway_and_redacted_members(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);binary=root/'docker';binary.write_text(FAKE.replace("elif '.State.Running' in f:print('false')","elif '.State.Running' in f:print('true')"));binary.chmod(0o700)
   marker=root/'mutation';env=os.environ.copy();env.update(PATH=str(root)+':'+env['PATH'],OBSERVER_MUTATION_MARKER=str(marker))
   r=subprocess.run(['bash',str(ROOT/'capture.sh')],env=env,capture_output=True,text=True,timeout=5)
   self.assertEqual(r.returncode,0)
   self.assertIn('gateway_topology_capture_complete running=true',r.stdout)
   self.assertNotIn('unrelated-private-service',r.stdout)
   self.assertNotIn('seal-3nol',r.stdout)
   self.assertFalse(marker.exists())
 def test_reader_rejects_env_values_and_unknown_fields(self):
  self.assertFalse(m.observer_record(json.dumps({'record':'env_name','role':'sealer','name':'SEALER_KEY=synthetic-secret'})))
  self.assertFalse(m.observer_record(json.dumps({'record':'env_name','role':'sealer','name':'SEALER_KEY','value':'synthetic-secret'})))
