import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).parents[1]
FAKE=r'''#!/usr/bin/env python3
import sys,os,json
from pathlib import Path
a=sys.argv[1:];path=Path(os.environ['OWNED_RESUME_STATE']);state=json.loads(path.read_text());g='643b1cc6f975dc11dbae9f3de7e8576b5922b502f3147ec6d076c7aea8902886';p='b'*64
source='44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5';image='wallet-security-mail-gateway:'+source
if a[0]=='ps':
 if os.environ.get('OWNED_RPC_FAIL')=='true':raise SystemExit(2)
 f=a[a.index('--filter')+1]
 if f=='name=^/wallet-security-mail-gateway$':print(g)
 elif f=='name=^/wallet-security-mail-gateway-probe$' and (state['probe'] or os.environ.get('OWNED_OLD_PROBE')=='true'):print(p)
elif a[0]=='inspect':
 f=a[a.index('-f')+1];target=a[-1];probe=target==p
 if probe and not state['probe']:raise SystemExit(1)
 if f=='{{.Id}}':print(p if probe else g)
 elif f=='{{.Name}}':print('/wallet-security-mail-gateway')
 elif f=='{{.Config.Image}}':print('wrong' if os.environ.get('OWNED_BAD_IMAGE')=='true' and not probe else image)
 elif 'org.opencontainers.image.revision' in f:print(source)
 elif 'com.cl8y.scope' in f:print('wallet-security-mail-gateway-preflight' if probe else 'wallet-security-mail-gateway')
 elif 'com.cl8y.owner' in f or 'com.docker.compose.project' in f:print('y08cgj4rjem3ldgfmxb11nsp')
 elif '.State.Running' in f:print('false' if probe else str(state['running']).lower())
 elif '.State.ExitCode' in f:print('0')
 elif '.Image' in f:print('sha256:'+'a'*64)
 elif '.NetworkSettings.Networks' in f:
  print('wallet-security-mailu-outbound='+('0'*64 if os.environ.get('OWNED_BAD_NETWORK')=='true' else '7afdb422fac3093083ba0ec34934a5acf381449c2cd6c09bb664e44f3b797d35'))
  print('wallet-security-notification=e1f3b89f1f7b590b7fa34def87b39521927b5b28d251189734ebd019b84081b4\n')
 else:raise SystemExit(1)
elif a[:2]==['network','inspect']:
 f=a[a.index('-f')+1]
 if '.Internal' in f:print('true' if a[-1]=='wallet-security-notification' else 'false')
 else:print('0')
elif a[0]=='start':
 if a[-1]==g:state['running']=True;state['starts']+=1
 elif a[-1]==p:
  state['probe_starts']+=1
  if os.environ.get('OWNED_TLS_FAIL')=='true':path.write_text(json.dumps(state));raise SystemExit(1)
  print('synthetic_owned_tls_only')
 else:raise SystemExit(1)
elif a[0]=='create':
 assert '--network' in a and a[a.index('--network')+1]=='wallet-security-notification'
 assert '--read-only' in a and '--cap-drop' in a and '--label' in a
 state['probe']=True;print(p)
 if os.environ.get('OWNED_PARTIAL_PROBE')=='true':path.write_text(json.dumps(state));raise SystemExit(1)
elif a[0]=='stop':
 if a[-1]==g:state['running']=False;state['stops']+=1
 elif a[-1]!=p:raise SystemExit(1)
elif a[0]=='rm':
 if os.environ.get('OWNED_REMOVE_FAIL')=='true':raise SystemExit(1)
 assert a[-1]==p
 if os.environ.get('OWNED_REMOVE_LEAK')!='true':state['probe']=False
else:raise SystemExit(1)
path.write_text(json.dumps(state))
'''
class Resume(unittest.TestCase):
 def run_case(self, activation=False, **flags):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);context=root/'context';context.mkdir();binary=root/'bin';binary.mkdir()
   for name in ('resume-preflight.sh','normalize-network-names.sh'):shutil.copyfile(ROOT/name,context/name)
   (context/'runtime-check.sh').write_text('#!/bin/bash\nexit 0\n')
   (binary/'docker').write_text(FAKE);(binary/'docker').chmod(0o700)
   path=root/'state';path.write_text(json.dumps({'running':False,'probe':False,'starts':0,'stops':0,'probe_starts':0}))
   env=os.environ.copy();env.update(PATH=str(binary)+':'+env['PATH'],OWNED_RESUME_STATE=str(path));env.update({k:str(v).lower() for k,v in flags.items()})
   r=subprocess.run(['bash',str(context/'resume-preflight.sh')]+(['--activate-retained'] if activation else []),env=env,capture_output=True,text=True,timeout=5)
   return r.returncode,json.loads(path.read_text()),r.stdout
 def test_success_stops_same_retained_cid_and_removes_probe(self):
  code,state,out=self.run_case();self.assertEqual(code,1);self.assertEqual(state['starts'],1);self.assertEqual(state['stops'],1);self.assertFalse(state['probe']);self.assertIn('gateway_noauth_tls_preflight_pass',out)
 def test_existing_probe_refused_without_gateway_start_or_stop(self):
  _,state,out=self.run_case(OWNED_OLD_PROBE=True);self.assertEqual(state['starts'],0);self.assertEqual(state['stops'],0);self.assertIn('preexisting_probe_refused',out)
 def test_rpc_failure_does_not_start_or_stop(self):
  _,state,_=self.run_case(OWNED_RPC_FAIL=True);self.assertEqual(state['starts'],0);self.assertEqual(state['stops'],0)
 def test_wrong_image_or_network_id_refused_before_start(self):
  for key in ('OWNED_BAD_IMAGE','OWNED_BAD_NETWORK'):
   _,state,_=self.run_case(**{key:True});self.assertEqual(state['starts'],0);self.assertEqual(state['stops'],0)
 def test_tls_failure_still_stops_gateway_and_removes_owned_probe(self):
  _,state,out=self.run_case(OWNED_TLS_FAIL=True);self.assertEqual(state['stops'],1);self.assertFalse(state['probe']);self.assertNotIn('gateway_noauth_tls_preflight_pass',out)
 def test_partial_probe_creation_is_cleaned_by_same_scope_gates(self):
  _,state,out=self.run_case(OWNED_PARTIAL_PROBE=True);self.assertEqual(state['stops'],1);self.assertFalse(state['probe']);self.assertIn('gateway_noauth_probe_cleanup=true',out)
 def test_activation_keeps_only_verified_gateway_after_owned_probe_cleanup(self):
  code,state,out=self.run_case(activation=True)
  self.assertEqual(code,1);self.assertTrue(state['running']);self.assertEqual(state['starts'],1);self.assertEqual(state['stops'],0);self.assertFalse(state['probe'])
  self.assertIn('gateway_activation_pass',out);self.assertIn('gateway_noauth_probe_cleanup=true',out)
 def test_activation_failure_or_cleanup_failure_never_commits_persistence(self):
  for flag in ('OWNED_TLS_FAIL','OWNED_PARTIAL_PROBE','OWNED_REMOVE_FAIL','OWNED_REMOVE_LEAK'):
   _,state,out=self.run_case(activation=True,**{flag:True})
   self.assertFalse(state['running']);self.assertEqual(state['stops'],1);self.assertNotIn('gateway_activation_pass',out)
