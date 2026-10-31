import hashlib
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).parents[1]
FILES=('Cargo.toml','Cargo.lock','Dockerfile','preflight.sh','src/main.rs')
class Inputs(unittest.TestCase):
 def fixture(self, valid):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);context=root/'context';context.mkdir();(context/'src').mkdir()
   for name in (*FILES,'build.sh'):shutil.copyfile(ROOT/name,context/name)
   binary=root/'bin';binary.mkdir();marker=root/'docker-called'
   manifest=''.join((hashlib.sha256((context/name).read_bytes()).hexdigest() if valid else '0'*64)+'  '+name+'\n' for name in FILES)
   (binary/'curl').write_text("#!/bin/sh\ncat <<'MANIFEST'\n"+manifest+'MANIFEST\n')
   (binary/'docker').write_text('#!/bin/sh\n: > "$OWNED_DOCKER_MARKER"\n')
   for name in ('curl','docker'):(binary/name).chmod(0o700)
   env=os.environ.copy();env.update(PATH=str(binary)+':'+env['PATH'],OWNED_DOCKER_MARKER=str(marker))
   result=subprocess.run(['bash',str(context/'build.sh'),'a'*40],env=env,capture_output=True,text=True,timeout=3)
   return result.returncode,marker.exists(),result.stdout
 def test_stripped_git_checkout_with_exact_inputs_is_accepted(self):
  code,docker,output=self.fixture(True)
  self.assertEqual(code,0);self.assertTrue(docker);self.assertIn('mail_gateway_image_inputs_verified',output)
 def test_changed_input_refused_before_docker(self):
  code,docker,output=self.fixture(False)
  self.assertNotEqual(code,0);self.assertFalse(docker);self.assertNotIn('mail_gateway_image_inputs_verified',output)
 def test_manifest_matches_tracked_image_inputs(self):
  actual=''.join(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in FILES)
  self.assertEqual((ROOT/'image-inputs.sha256').read_text(),actual)
if __name__=='__main__':unittest.main()
