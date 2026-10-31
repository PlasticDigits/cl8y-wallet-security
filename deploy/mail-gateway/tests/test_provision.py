import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('gateway',Path(__file__).parents[1]/'provision.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
APP='aaaaaaaaaaaaaaaaaaaaaaaa'
SHA='a'*40
BRANCH='bb/test-gateway'
def app():
 return dict(name=m.NAME,git_repository=m.REPO,docker_compose_location=m.COMPOSE,
  environment={'uuid':m.ENVIRONMENT},destination={'uuid':m.DESTINATION})
class Scope(unittest.TestCase):
 def test_commands_fit_maximum_identifier_before_mutations(self):
  build,start=m.commands('a'*32,SHA)
  self.assertLessEqual(max(len(build.encode()),len(start.encode())),255)
  self.assertNotIn('up -d',start)
 def test_refuses_portal_before_api_mutation(self):
  with patch.object(m,'api') as api:
   with self.assertRaisesRegex(RuntimeError,'portal_refused'):m.owned(m.PORTAL)
   api.assert_not_called()
 def test_unrelated_resource_is_never_adopted(self):
  with patch.object(m,'api',return_value={'name':'unrelated'}) as api:
   with self.assertRaisesRegex(RuntimeError,'resource_identity_conflict'):m.owned(APP)
   self.assertEqual(api.call_count,1)
 def test_create_is_separate_and_disabled(self):
  calls=[]
  def api(method,path,data=None):
   calls.append((method,path,data))
   if method=='GET':return []
   self.assertEqual(path,'/applications/public');return {'uuid':APP}
  remote=subprocess.CompletedProcess([],0,SHA+'\trefs/heads/'+BRANCH+'\n','')
  with patch.object(sys,'argv',['provision','--create','--sha',SHA,'--branch',BRANCH]),patch.object(m,'api',side_effect=api),patch.object(m.subprocess,'run',return_value=remote),contextlib.redirect_stdout(io.StringIO()):m.main()
  data=calls[1][2]
  for k in ('instant_deploy','is_auto_deploy_enabled','is_preview_deployments_enabled','inject_build_args_to_dockerfile','include_coolify_default_variables'):self.assertIs(data[k],False)
  self.assertTrue(data['is_raw_compose_deployment_enabled'])
  self.assertEqual(data['git_commit_sha'],SHA)
  self.assertNotIn('TOKEN',json.dumps(data))
 def test_only_closed_own_deployment_receipts_escape(self):
  receipt='mail_gateway_preflight_pass uid=10001 no_default_route=true alias_private=true hostname_verified=true direct_mailu_denied=true other_targets_denied=true auth=false sends=0'
  deployment=dict(application_name=m.NAME,status='finished',logs=json.dumps([{'output':'synthetic-secret-provider-body'},{'output':receipt},{'output':receipt+' credential=synthetic-secret'}]))
  with patch.object(sys,'argv',['provision','--app',APP,'--deployment','bbbbbbbbbbbbbbbbbbbbbbbb','--receipts']),patch.object(m,'api',side_effect=[app(),deployment]),contextlib.redirect_stdout(io.StringIO()) as output:m.main()
  self.assertEqual(output.getvalue(),receipt+'\n')
if __name__=='__main__':unittest.main()
