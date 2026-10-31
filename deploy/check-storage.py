import os,subprocess,secrets,time,pathlib,json
root=str(pathlib.Path.cwd());name='wallet-security-deploy-sandbox-'+secrets.token_hex(4)
env={**os.environ,'POSTGRES_PASSWORD':secrets.token_hex(32),'POSTGRES_DB':'wallet_security','BACKUP_ONCE':'true'}
for k in ['DB_MIGRATOR_PASSWORD','DB_API_PASSWORD','DB_WORKER_PASSWORD','DB_BACKUP_PASSWORD']:env[k]=secrets.token_hex(32)
def run(args,input=None,check=True):
 r=subprocess.run(args,input=input,text=True,capture_output=True,env=env,timeout=150)
 if check and r.returncode:
  for text in ['Permission denied','permission denied','could not connect','could not open','Connection refused','password authentication failed','not found','could not translate host name','not permitted','does not exist','no password supplied']:
   if text in r.stderr: print('error_category',text)
  raise RuntimeError('command failed: '+args[0]+' '+args[1]+' rc='+str(r.returncode))
 return r
def sql(s):return run(['docker','exec','-i',name,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','wallet_security'],s)
try:
 run(['docker','run','-d','--name',name,'--hostname','postgres','--network','none','--user','postgres','--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/var/lib/postgresql/data:uid=999,gid=999','--tmpfs','/backups:uid=999,gid=999','-v',root+'/deploy/postgres-init.sh:/docker-entrypoint-initdb.d/10-roles.sh:ro','-v',root+'/deploy:/app/deploy:ro',*[p for k in ['POSTGRES_PASSWORD','POSTGRES_DB','DB_MIGRATOR_PASSWORD','DB_API_PASSWORD','DB_WORKER_PASSWORD','DB_BACKUP_PASSWORD'] for p in ['-e',k]],'postgres:17.6-bookworm@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3'])
 for _ in range(30):
  if run(['docker','exec',name,'pg_isready','-U','postgres'],check=False).returncode==0:break
  time.sleep(.5)
 time.sleep(1)
 sql('SET ROLE security_migrator;\n'+pathlib.Path('api/migrations/0001_foundation.sql').read_text()+'\nCREATE TABLE _sqlx_migrations(version bigint,success bool);INSERT INTO _sqlx_migrations VALUES(1,true);')
 sql('SET ROLE security_migrator;\n'+pathlib.Path('deploy/grants.sql').read_text())
 checks={}
 for role in ['security_api','security_worker']:
  for label,statement in [('ddl','CREATE TABLE should_fail(id int)'),('history_write','DELETE FROM _sqlx_migrations')]:
   r=run(['docker','exec','-i',name,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U',role,'-d','wallet_security'],statement,check=False)
   checks[role+'_'+label+'_denied']=r.returncode!=0
 checks['api_dml']=sql("BEGIN;SET ROLE security_api;INSERT INTO profiles(id,anchor_wallet) VALUES('00000000-0000-0000-0000-000000000001','sandbox-owned');ROLLBACK;").returncode==0
 checks['backup_read_only']=run(['docker','exec','-i',name,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','security_backup','-d','wallet_security'],'DELETE FROM profiles;',check=False).returncode!=0
 env['DATABASE_URL']='postgresql://security_backup:'+env['DB_BACKUP_PASSWORD']+'@localhost:5432/wallet_security'
 run(['docker','exec','-e','DATABASE_URL','-e','BACKUP_ONCE',name,'bash','/app/deploy/backup.sh'])
 env['DATABASE_URL']='postgresql://postgres:'+env['POSTGRES_PASSWORD']+'@localhost:5432/wallet_security'
 r=run(['docker','exec','-e','DATABASE_URL',name,'bash','/app/deploy/restore-drill.sh'])
 checks['backup_restore']=r.returncode==0
 print(json.dumps(checks,sort_keys=True));print(r.stdout.strip())
 if not all(checks.values()):raise RuntimeError('deployment assertion failed')
finally:run(['docker','rm','-f',name],check=False)
