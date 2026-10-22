"""Check that a paused PostgreSQL backend cannot hold /health beyond two seconds.

Requires local PostgreSQL server binaries and `pgrep`. Creates and removes a disposable
cluster with a random SCRAM password and a loopback-only listener.
Run: python3 scripts/probe_health_backend_timeout.py /absolute/path/to/request-guard-mcp
"""

import argparse
import getpass
import json
import os
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

PG=subprocess.check_output(['pg_config','--bindir'],text=True).strip()
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary')
args=parser.parse_args()
BIN=os.path.abspath(args.binary)
def port():
 s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p
def probe(p, path):
 start=time.monotonic()
 try:
  with urllib.request.urlopen(f'http://127.0.0.1:{p}{path}',timeout=8) as r:
   out=str(r.status);body=r.read()
 except urllib.error.HTTPError as e:out=str(e.code);body=e.read()
 except Exception as e:out=type(e).__name__;body=b''
 status=json.loads(body)['status'] if path=='/health' and out=='200' else None
 return out,round(time.monotonic()-start,3),status
with tempfile.TemporaryDirectory(prefix='rg-pg-probe-') as td:
 data=td+'/data';pgport=port();rgport=port()
 password=secrets.token_hex(32)
 subprocess.run(
  [PG+'/initdb','-A','scram-sha-256','--pwfile','/dev/stdin','--no-instructions','-D',data],
  input=password+'\n',text=True,check=True,stdout=subprocess.DEVNULL,
 )
 start=subprocess.run([PG+'/pg_ctl','-D',data,'-o',f'-h 127.0.0.1 -p {pgport} -k {td}','-l',td+'/pg.log','start'],stdout=subprocess.DEVNULL)
 if start.returncode:
  print(open(td+'/pg.log').read()[-1000:]);raise RuntimeError('pg_ctl start failed')
 env=os.environ.copy();env.update(MCP__HOST='127.0.0.1',MCP__PORT=str(rgport),MCP__POSTGRES__URL=f'postgres://{getpass.getuser()}:{password}@127.0.0.1:{pgport}/postgres',MCP__LIMITS__MAX_CONNECTIONS='2',AUTH_TOKENS='test-only-token-abcdefghijklmnopqrstuvwxyz123456',CACHE_SCOPE_HMAC_KEY='test-only-hmac-key-abcdefghijklmnopqrstuvwxyz123456',LOG_LEVEL='error')
 p=subprocess.Popen([BIN],cwd=td,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 stopped=[]
 try:
  for _ in range(100):
   if p.poll() is not None:raise RuntimeError('server exited: '+p.stderr.read()[-1000:])
   result=probe(rgport,'/health')
   if result[0]=='200' and result[2]=='healthy':break
   time.sleep(.1)
  else:raise RuntimeError('server startup timed out')
  postmaster=int(open(data+'/postmaster.pid').readline())
  children=subprocess.check_output(['pgrep','-P',str(postmaster)],text=True).split()
  stopped=[int(x) for x in children]+[postmaster]
  for pid in stopped:os.kill(pid,signal.SIGSTOP)
  print('paused_postgres_processes',len(stopped),flush=True)
  for path,expected in (('/health','200'),('/ready','503')):
   result=probe(rgport,path)
   print(path,'during_pg_stall',result,flush=True)
   assert result[0]==expected and result[1]<2, f'{path} exceeded two-second deadline'
   if path=='/health':assert result[2]=='unhealthy', 'health body did not degrade'
 finally:
  for pid in reversed(stopped):
   try:os.kill(pid,signal.SIGCONT)
   except ProcessLookupError:pass
  p.terminate()
  try:p.wait(timeout=2)
  except subprocess.TimeoutExpired:p.kill();p.wait()
  subprocess.run([PG+'/pg_ctl','-D',data,'stop','-m','immediate'],stdout=subprocess.DEVNULL,check=False)
