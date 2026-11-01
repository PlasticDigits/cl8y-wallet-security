import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).parents[1]
FAKE=r'''#!/usr/bin/env python3
import sys,os
from pathlib import Path
a=sys.argv[1:]
if a[0]=='ps':raise SystemExit(0)
if a[0]=='create':
 assert a[a.index('--network')+1]=='none';print('b'*64);raise SystemExit(0)
if a[0]=='rm':raise SystemExit(0)
if a[0] not in ('inspect','image'):
 Path(os.environ['START_MARKER']).write_text('unexpected runtime mutation');raise SystemExit(1)
f=a[a.index('-f')+1];drift=os.environ.get('DRIFT','')
if '.Config.User' in f:print('10001:10001')
elif '.Config.Image' in f:print('wallet-security-mail-gateway:44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5')
elif 'org.opencontainers.image.revision' in f:print('44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5')
elif 'com.cl8y.scope' in f:print('wallet-security-mail-gateway-binding')
elif 'com.cl8y.owner' in f:print('y08cgj4rjem3ldgfmxb11nsp')
elif f in ('{{.Image}}','{{.Id}}'):print('sha256:'+'a'*64)
elif '.State.Running' in f:print('false')
elif '.ReadonlyRootfs' in f:print('true')
elif 'len .HostConfig.PortBindings' in f or 'len .Mounts' in f or 'len .HostConfig.CapAdd' in f:print('0')
elif '.Privileged' in f:print('false')
elif '.CapDrop' in f:print('["ALL"]')
elif 'traefik.enable' in f:print('false')
elif '.LogConfig.Type' in f:print('none')
elif '.Config.Env' in f:
 assert 'split . "="' in f;print('PATH')
elif '.Memory' in f:print('0' if drift=='memory' else '67108864')
elif '.NanoCpus' in f:print('0' if drift=='cpu' else '100000000')
elif '.PidsLimit' in f:print('-1' if drift=='pids' else '16')
elif '.SecurityOpt' in f:print('["no-new-privileges:false"]' if drift=='nnp' else '["no-new-privileges:true"]')
else:raise SystemExit(1)
'''
class Bounds(unittest.TestCase):
 def run_case(self,drift=''):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);docker=root/'docker';docker.write_text(FAKE);docker.chmod(0o700);marker=root/'started'
   env=os.environ.copy();env.update(PATH=str(root)+':'+env['PATH'],DRIFT=drift,START_MARKER=str(marker))
   r=subprocess.run(['bash',str(ROOT/'runtime-check.sh'),'44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5','identity-only'],env=env,capture_output=True,text=True,timeout=5)
   return r.returncode,r.stdout,marker.exists()
 def test_matching_stopped_identity_and_bounds_pass_without_start(self):
  code,out,started=self.run_case();self.assertEqual(code,0);self.assertIn('gateway_prestart_identity_verified',out);self.assertFalse(started)
 def test_all_resource_drift_fails_before_start(self):
  for field in ('memory','cpu','pids','nnp'):
   code,out,started=self.run_case(field);self.assertNotEqual(code,0,field);self.assertIn('stage=resource_bounds',out);self.assertFalse(started)
