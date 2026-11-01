from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).parents[1]
EXPECTED=b'wallet-security-mailu-outbound\nwallet-security-notification'
class Names(unittest.TestCase):
 def normalize(self,data):
  return subprocess.run(['bash',str(ROOT/'normalize-network-names.sh')],input=data,capture_output=True,check=True,timeout=2).stdout.rstrip(b'\n')
 def test_docker_outer_newline_no_longer_becomes_leading_name(self):
  raw=EXPECTED+b'\n\n'
  old=subprocess.run(['sort'],input=raw,capture_output=True,check=True,timeout=2).stdout.rstrip(b'\n')
  self.assertEqual(old,b'\n'+EXPECTED)
  self.assertNotEqual(old,EXPECTED)
  self.assertEqual(self.normalize(raw),EXPECTED)
 def test_extra_nonempty_network_still_refused(self):
  self.assertNotEqual(self.normalize(EXPECTED+b'\n\ncoolify\n'),EXPECTED)
 def test_duplicate_identity_not_collapsed(self):
  self.assertNotEqual(self.normalize(EXPECTED+b'\nwallet-security-notification\n'),EXPECTED)
 def test_prefix_mismatch_not_rewritten(self):
  self.assertNotEqual(self.normalize(EXPECTED.replace(b'wallet-security-notification',b'y08_wallet-security-notification')+b'\n'),EXPECTED)
 def test_only_truly_empty_separator_lines_removed(self):
  self.assertNotEqual(self.normalize(EXPECTED+b'\n \n'),EXPECTED)
