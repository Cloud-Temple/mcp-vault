"""Isolated OpenBao 2.5.1 contract test. No production config, network or credentials."""
import asyncio, base64, hashlib, hmac, json, secrets, subprocess, sys, tempfile, time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock
import hvac, httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from mcp_vault.vault import pki_ca
from mcp_vault.pki_middleware import PkiMiddleware, _ROLE_ACME_PATH
OUT=Path(tempfile.mkdtemp(prefix='mcp-vault-role-acme-'))
NAME='dbaas-pki-contract-'+secrets.token_hex(4)
IMAGE='openbao/openbao@sha256:87d715029a47328172774638cabfeb04d5b356678d660621b796b6a671f93581'
TOKEN=secrets.token_urlsafe(24)
report={'image':IMAGE,'results':{},'limits':['S3 upload mocked; no durability proof','Local HTTP only; WAF/TLS/DNS-01 issuance not covered','No production state or credentials']}
def docker(*args):
 return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.PIPE).strip()
def check(name,condition,detail=None):
 report['results'][name]={'pass':bool(condition),'detail':detail}
 if not condition: raise AssertionError(name)
def b64(v): return base64.urlsafe_b64encode(v).rstrip(b'=').decode()
def compact(v): return json.dumps(v,separators=(',',':')).encode()
async def main(addr):
 c=hvac.Client(url=addr,token=TOKEN,timeout=10)
 check('runtime_version', c.sys.read_health_status(method='GET')['version']=='2.5.1')
 sync=AsyncMock(return_value=True)
 base='http://pki.example.test'
 async def setup():
  with patch.object(pki_ca,'_get_hvac_client',return_value=c),patch.object(pki_ca,'_base_url',return_value=base),patch('mcp_vault.s3_sync.upload_to_s3',sync):
   return await pki_ca.setup_pki_ca(lab_mode=False,allowed_domains=['internal.example.test'],leaf_ttl='2h')
 check('unmounted_read_is_none', c.read('_sys_pki_int/config/acme') is None)
 first=await setup()
 check('first_setup',first.get('status')=='ok',first.get('message'))
 role=c.read('_sys_pki_int/roles/acme-servers')['data']
 role['allowed_domains']=['dbaas.internal.example.test']
 c.write('_sys_pki_int/roles/dbaas-servers',**role)
 cfg=c.read('_sys_pki_int/config/acme')['data']
 cfg['allowed_roles']=['acme-servers','dbaas-servers']
 c.write('_sys_pki_int/config/acme',**cfg)
 root_before=c.read('_sys_pki_root/cert/ca')['data']['certificate']
 role_before=c.read('_sys_pki_int/roles/dbaas-servers')['data']
 second=await setup()
 check('second_setup',second.get('status')=='ok',second.get('message'))
 after=c.read('_sys_pki_int/config/acme')['data']
 check('named_roles_preserved',after['allowed_roles']==['acme-servers','dbaas-servers'],after['allowed_roles'])
 check('eab_stays_required',after['eab_policy']=='new-account-required',after['eab_policy'])
 check('dbaas_role_unchanged',c.read('_sys_pki_int/roles/dbaas-servers')['data']==role_before)
 check('root_unchanged',c.read('_sys_pki_root/cert/ca')['data']['certificate']==root_before)
 async def inner(scope,receive,send):
  await send({'type':'http.response.start','status':404,'headers':[]})
  await send({'type':'http.response.body','body':b'not-proxied'})
 with patch('mcp_vault.pki_middleware.get_settings',return_value=SimpleNamespace(openbao_addr=addr)):
  async with httpx.AsyncClient(transport=httpx.ASGITransport(app=PkiMiddleware(inner)),base_url=base) as http:
   directory_path='/v1/_sys_pki_int/roles/dbaas-servers/acme/directory'
   r=await http.get(directory_path)
   check('real_directory_through_proxy',r.status_code==200,r.status_code)
   directory=r.json()
   urls={k:v for k,v in directory.items() if isinstance(v,str) and v.startswith('http')}
   check('all_advertised_paths_supported',all(_ROLE_ACME_PATH.fullmatch(httpx.URL(v).path) for v in urls.values()),urls)
   nonce=await http.head(directory['newNonce'])
   check('nonce_header_survives',nonce.status_code==200 and bool(nonce.headers.get('replay-nonce')),nonce.status_code)
   denied=await http.post('/v1/_sys_pki_int/roles/dbaas-servers/acme/new-eab')
   check('operator_route_not_proxied',denied.status_code==404 and denied.text=='not-proxied')
   key=ec.generate_private_key(ec.SECP256R1()); nums=key.public_key().public_numbers()
   jwk={'kty':'EC','crv':'P-256','x':b64(nums.x.to_bytes(32,'big')),'y':b64(nums.y.to_bytes(32,'big'))}
   async def signed(url,payload,kid=None):
    n=await http.head(directory['newNonce'])
    protected={'alg':'ES256','nonce':n.headers['replay-nonce'],'url':url}
    protected.update({'kid':kid} if kid else {'jwk':jwk})
    p=b64(compact(protected)); body=b64(compact(payload) if payload is not None else b'')
    rr,ss=decode_dss_signature(key.sign((p+'.'+body).encode(),ec.ECDSA(hashes.SHA256())))
    return await http.post(url,json={'protected':p,'payload':body,'signature':b64(rr.to_bytes(32,'big')+ss.to_bytes(32,'big'))},headers={'Content-Type':'application/jose+json'})
   no_eab=await signed(directory['newAccount'],{'termsOfServiceAgreed':True})
   check('account_without_eab_rejected',no_eab.status_code>=400 and 'externalAccountRequired' in no_eab.text,{'status':no_eab.status_code,'type':no_eab.json().get('type')})
   eab=c.write('_sys_pki_int/roles/dbaas-servers/acme/new-eab')['data']
   protected=b64(compact({'alg':'HS256','kid':eab['id'],'url':directory['newAccount']})); payload=b64(compact(jwk))
   hk=base64.urlsafe_b64decode(eab['key']+'='*(-len(eab['key'])%4))
   binding={'protected':protected,'payload':payload,'signature':b64(hmac.new(hk,(protected+'.'+payload).encode(),hashlib.sha256).digest())}
   account=await signed(directory['newAccount'],{'termsOfServiceAgreed':True,'externalAccountBinding':binding})
   check('eab_account_through_proxy',account.status_code==201,{'status':account.status_code,'body':account.json() if account.status_code!=201 else 'created'})
   kid=account.headers['location']
   check('account_location_supported',bool(_ROLE_ACME_PATH.fullmatch(httpx.URL(kid).path)))
   order=await signed(directory['newOrder'],{'identifiers':[{'type':'dns','value':'node.dbaas.internal.example.test'}]},kid)
   check('real_order_through_proxy',order.status_code==201,{'status':order.status_code})
   order_urls=[order.headers['location'],order.json()['finalize'],*order.json()['authorizations']]
   check('order_paths_supported',all(_ROLE_ACME_PATH.fullmatch(httpx.URL(v).path) for v in order_urls),order_urls)
   authorization=await signed(order.json()['authorizations'][0],None,kid)
   check('authorization_through_proxy',authorization.status_code==200,authorization.status_code)
   challenge_urls=[x['url'] for x in authorization.json()['challenges']]
   check('challenge_paths_supported',bool(challenge_urls) and all(_ROLE_ACME_PATH.fullmatch(httpx.URL(v).path) for v in challenge_urls),challenge_urls)
 # Reviewer hypothesis: deleting an allowed role makes subsequent setup fail.
 c.delete('_sys_pki_int/roles/dbaas-servers')
 writes=[]
 original_write=c.write
 original_post=c._adapter.post
 def track_write(*args,**kwargs):
  writes.append(args[0]); return original_write(*args,**kwargs)
 def track_post(*args,**kwargs):
  writes.append(args[0]); return original_post(*args,**kwargs)
 with patch.object(c,'write',side_effect=track_write),patch.object(c._adapter,'post',side_effect=track_post):
  deleted=await setup()
 check('deleted_role_fail_before_write',deleted.get('status')=='error' and writes==[],{'status':deleted.get('status'),'writes':writes})
 report['results']['setup_with_deleted_role']={'pass':deleted.get('status')=='error','detail':deleted.get('message'),'allowed_roles':c.read('_sys_pki_int/config/acme')['data']['allowed_roles']}
 report['sync_stub_calls']=sync.await_count
try:
 docker('run','-d','--name',NAME,'--label','purpose=dbaas-pr177-isolated-test','--memory','512m','--cpus','2','-p','127.0.0.1::8200','-e','BAO_DEV_ROOT_TOKEN_ID='+TOKEN,IMAGE,'server','-dev','-dev-listen-address=0.0.0.0:8200')
 port=docker('port',NAME,'8200/tcp').rsplit(':',1)[1]; addr='http://127.0.0.1:'+port
 for _ in range(30):
  try:
   if httpx.get(addr+'/v1/sys/health',timeout=1).status_code==200: break
  except httpx.HTTPError: pass
  time.sleep(.2)
 else: raise RuntimeError('isolated OpenBao not ready')
 asyncio.run(main(addr))
 report['completed']=True
except Exception as e:
 report['completed']=False; report['error']=type(e).__name__+': '+str(e)
finally:
 docker('rm','-f',NAME)
 (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))
 print('Receipt:', OUT/'result.json')
 if not report.get('completed') or not all(v['pass'] for v in report['results'].values()):
  sys.exit(1)
