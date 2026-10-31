import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).parents[1]
SOURCE='44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5'
DOCKER=r'''#!/usr/bin/env python3
import os,sys
from pathlib import Path
a=sys.argv[1:];state=Path(os.environ['OWNED_STATE']);stopped=Path(os.environ['OWNED_STOPPED'])
if a[:2]==['image','inspect']:print('44a2d3604b2051278aafcfa80fa4e19f4eb6c1d5')
elif a[0]=='inspect':
 if not state.exists():raise SystemExit(1)
 f=a[a.index('-f')+1]
 if '.Id' in f:print('a'*64)
 elif 'com.cl8y.scope' in f:print('wallet-security-mail-gateway')
 elif 'com.docker.compose.project' in f:print('y08cgj4rjem3ldgfmxb11nsp')
 else:raise SystemExit(1)
elif a[0]=='compose':
 assert '--no-build' in a and '--env-file' in a and a[a.index('--env-file')+1]=='/dev/null'
 assert 'services:' in sys.stdin.read();state.write_text('created')
elif a[0]=='stop':
 assert a[-1]=='a'*64;stopped.write_text('stopped')
else:raise SystemExit(1)
'''
class Reproduction(unittest.TestCase):
 def run_case(self, guard_code=1, corrupt=False, preexisting=False):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);context=root/'context';context.mkdir();binary=root/'bin';binary.mkdir()
   shutil.copyfile(ROOT/'reproduce.sh',context/'reproduce.sh')
   (context/'runtime-check.sh').write_text('#!/bin/bash\nexit '+str(guard_code)+'\n')
   (binary/'docker').write_text(DOCKER);(binary/'docker').chmod(0o700)
   (binary/'curl').write_text('#!/bin/sh\ncat "$OWNED_RAW"\n');(binary/'curl').chmod(0o700)
   raw=root/'raw';raw.write_bytes(b'wrong\n' if corrupt else (ROOT/'compose.yml').read_bytes())
   state=root/'state';stopped=root/'stopped'
   if preexisting:state.write_text('old')
   env=os.environ.copy();env.update(PATH=str(binary)+':'+env['PATH'],OWNED_STATE=str(state),OWNED_STOPPED=str(stopped),OWNED_RAW=str(raw))
   r=subprocess.run(['bash',str(context/'reproduce.sh')],env=env,capture_output=True,text=True,timeout=5)
   return r.returncode,state.exists(),stopped.exists(),r.stdout
 def test_guard_failure_stops_and_retains_only_owned_container(self):
  code,created,stopped,output=self.run_case(1)
  self.assertEqual(code,1);self.assertTrue(created);self.assertTrue(stopped)
  self.assertIn('gateway_topology_cleanup_owned_stopped_retained=true',output)
 def test_success_is_still_not_release_and_stops(self):
  code,created,stopped,output=self.run_case(0)
  self.assertEqual(code,1);self.assertTrue(stopped)
  self.assertIn('diagnostic_complete_not_runtime_acceptance=true',output)
 def test_wrong_raw_bytes_refused_before_creation(self):
  code,created,stopped,_=self.run_case(corrupt=True)
  self.assertEqual(code,1);self.assertFalse(created);self.assertFalse(stopped)
 def test_preexisting_container_is_never_adopted_or_stopped(self):
  code,_,stopped,output=self.run_case(preexisting=True)
  self.assertEqual(code,1);self.assertFalse(stopped)
  self.assertIn('preexisting_container_refused',output)
