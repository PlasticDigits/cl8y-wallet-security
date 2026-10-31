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
  self.assertNotIn('--env-file',build)
  self.assertIn('bash deploy/mail-gateway/build.sh '+SHA,build)
  self.assertNotIn('docker compose',build)
  self.assertNotRegex(build,r'[|;]')
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
 def test_actual_deploy_path_uses_bounded_commands_on_max_identifier(self):
  target='a'*32
  calls=[]
  build,start=m.commands(target,SHA)
  actual=app();actual.update(settings={'is_raw_compose_deployment_enabled':True,'inject_build_args_to_dockerfile':False},docker_compose_custom_build_command=build,docker_compose_custom_start_command=start)
  responses=[app(),[],{}, {},actual,{'deployments':[{'deployment_uuid':'b'*24}]}]
  def api(method,path,data=None):
   calls.append((method,path,data));return responses.pop(0)
  remote=subprocess.CompletedProcess([],0,SHA+'\trefs/heads/'+BRANCH+'\n','')
  with patch.object(sys,'argv',['provision','--app',target,'--sha',SHA,'--branch',BRANCH]),patch.object(m,'api',side_effect=api),patch.object(m.subprocess,'run',return_value=remote),contextlib.redirect_stdout(io.StringIO()):m.main()
  for method,path,data in calls:
   if method in ('PATCH','POST'):
    self.assertTrue(path.startswith('/applications/'+target) or (path=='/deploy' and data['uuid']==target))
    for key in ('docker_compose_custom_build_command','docker_compose_custom_start_command'):
     if key in data:self.assertLessEqual(len(data[key].encode()),255)
  self.assertFalse(responses)
 def test_observer_preserves_env_and_start_hook_and_scopes_deploy(self):
  calls=[]
  actual=app();actual.update(git_commit_sha=SHA,settings={'is_raw_compose_deployment_enabled':True},docker_compose_custom_build_command='timeout 35 bash deploy/mail-gateway/observe.sh')
  responses=[app(),{},actual,{'deployments':[{'deployment_uuid':'b'*24}]}]
  def api(method,path,data=None):calls.append((method,path,data));return responses.pop(0)
  remote=subprocess.CompletedProcess([],0,SHA+'\trefs/heads/'+BRANCH+'\n','')
  with patch.object(sys,'argv',['provision','--app',APP,'--sha',SHA,'--branch',BRANCH,'--observe']),patch.object(m,'api',side_effect=api),patch.object(m.subprocess,'run',return_value=remote),contextlib.redirect_stdout(io.StringIO()):m.main()
  self.assertFalse(any(path.endswith('/envs') for _,path,_ in calls))
  self.assertNotIn('docker_compose_custom_start_command',calls[1][2])
  self.assertEqual(calls[-1],('POST','/deploy',{'uuid':APP,'force':False}))
 def test_reproduction_hook_is_distinct_and_preserves_release_fields(self):
  calls=[];actual=app();actual.update(git_commit_sha=SHA,settings={'is_raw_compose_deployment_enabled':True},docker_compose_custom_build_command='timeout 45 bash deploy/mail-gateway/reproduce.sh')
  responses=[app(),{},actual,{'deployments':[{'deployment_uuid':'b'*24}]}]
  def api(method,path,data=None):calls.append((method,path,data));return responses.pop(0)
  remote=subprocess.CompletedProcess([],0,SHA+'\trefs/heads/'+BRANCH+'\n','')
  with patch.object(sys,'argv',['provision','--app',APP,'--sha',SHA,'--branch',BRANCH,'--reproduce']),patch.object(m,'api',side_effect=api),patch.object(m.subprocess,'run',return_value=remote),contextlib.redirect_stdout(io.StringIO()) as output:m.main()
  self.assertFalse(any(path.endswith('/envs') for _,path,_ in calls))
  self.assertNotIn('docker_compose_custom_start_command',calls[1][2])
  self.assertIn('"topology_reproduction_only": true',output.getvalue())
 def test_only_closed_own_deployment_receipts_escape(self):
  receipt='mail_gateway_preflight_pass uid=10001 no_default_route=true alias_private=true hostname_verified=true direct_mailu_denied=true other_targets_denied=true auth=false sends=0'
  deployment=dict(application_name=m.NAME,status='finished',logs=json.dumps([{'output':'synthetic-secret-provider-body'},{'output':receipt},{'output':receipt+' credential=synthetic-secret'}]))
  with patch.object(sys,'argv',['provision','--app',APP,'--deployment','bbbbbbbbbbbbbbbbbbbbbbbb','--receipts']),patch.object(m,'api',side_effect=[app(),deployment]),contextlib.redirect_stdout(io.StringIO()) as output:m.main()
  self.assertEqual(output.getvalue(),receipt+'\n')
if __name__=='__main__':unittest.main()
