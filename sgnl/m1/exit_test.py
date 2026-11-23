# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

import json, base64, http.client, urllib.parse
BASE='/realms/test'; ISS='https://id.example.com/realms/test'
H={'X-Forwarded-Proto':'https','X-Forwarded-Host':'id.example.com','Host':'id.example.com'}
KC='$argon2id$v=19$m=7168,t=5,p=1$dk016MYDrSYOe3uI8Hj8Hg$JkADnvsSGzIE22w4StMki1156N6zJRBSoOA2GZ/j17s'
results=[]
def check(name, ok, detail=''):
    results.append(ok); print(('PASS ' if ok else 'FAIL ')+name+(f'  [{detail}]' if detail and not ok else ''))
class Client:
    def __init__(s): s.cookies={}
    def req(s,m,p,body=None,headers=None,form=False):
        c=http.client.HTTPConnection('127.0.0.1',9091); h=dict(H); h.update(headers or {})
        if s.cookies: h['Cookie']='; '.join(f'{k}={v}' for k,v in s.cookies.items())
        data=None
        if body is not None:
            if form: data=urllib.parse.urlencode(body); h['Content-Type']='application/x-www-form-urlencoded'
            else: data=json.dumps(body); h['Content-Type']='application/json'
        c.request(m,BASE+p,data,h); r=c.getresponse(); b=r.read().decode()
        for k,v in r.getheaders():
            if k.lower()=='set-cookie': n,val=v.split(';')[0].split('=',1); s.cookies[n]=val
        return r.status,dict(r.getheaders()),b
basic=lambda cid: {'Authorization':'Basic '+base64.b64encode(f'{cid}:insecure_secret'.encode()).decode()}
def claims(jwt): return json.loads(base64.urlsafe_b64decode(jwt.split('.')[1]+'=='))
api=Client()
st,_,b=api.req('POST','/api/oidc/token',{'grant_type':'client_credentials','scope':'authelia.admin.read authelia.admin.write','audience':ISS+'/api/admin'},basic('agent'),form=True)
at=json.loads(b)['access_token']; A={'Authorization':'Bearer '+at}
check('agent gets a client-credentials token', st==200)
st,_,b=api.req('POST','/api/admin/groups',{'name':'sgnl_users'},A); check('agent creates group', st in (201,409), b)
st,_,b=api.req('POST','/api/admin/users',{'username':'KC.User','email':'KC.User@Example.com','display_name':'KC User','given_name':'KC','family_name':'User','groups':['sgnl_users'],'password_digest':KC},A)
check('agent imports user with Keycloak argon2id digest', st==201, b)
u=Client()
st,_,b=u.req('POST','/api/firstfactor',{'username':'kc.user@example.com','password':'test-pass-123'})
check('imported user logs in by email with the Keycloak password', st==200, b)
q=urllib.parse.urlencode({'client_id':'app','response_type':'code','scope':'openid profile email groups offline_access','redirect_uri':'https://app.example.com/cb','state':'abcdefgh12345678','nonce':'n0ncen0ncen0nce1'})
st,h,b=u.req('GET','/api/oidc/authorization?'+q); loc=h.get('Location','')
if 'flow_id=' in loc:
    flow=urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)['flow_id'][0]
    st,_,b=u.req('POST','/api/oidc/consent',{'flow_id':flow,'client_id':'app','consent':True,'pre_configure':False})
    p=urllib.parse.urlparse(json.loads(b)['data']['redirect_uri']); st,h,b=u.req('GET',p.path[len(BASE):]+'?'+p.query); loc=h.get('Location','')
code=urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)['code'][0]
st,_,b=u.req('POST','/api/oidc/token',{'grant_type':'authorization_code','code':code,'redirect_uri':'https://app.example.com/cb'},basic('app'),form=True)
t=json.loads(b); idt=claims(t['id_token'])
check('ID token carries groups, email, name, preferred_username', idt.get('groups')==['sgnl_users'] and idt.get('email')=='kc.user@example.com' and idt.get('name')=='KC User' and idt.get('preferred_username')=='kc.user', json.dumps(idt))
check('ID token issuer is the realm path', idt.get('iss')==ISS, idt.get('iss'))
check('access token is a JWT (OpenCloud-style clients)', t['access_token'].count('.')==2)
st,_,b=api.req('PATCH','/api/admin/users/kc.user',{'disabled':True},A); check('agent disables user', st==200, b)
st,_,b=u.req('POST','/api/oidc/token',{'grant_type':'refresh_token','refresh_token':t['refresh_token']},basic('app'),form=True)
check('refresh token refused for disabled user', st==400 and 'invalid_grant' in b, b[:120])
st,_,b=api.req('PATCH','/api/admin/users/kc.user',{'disabled':False},A)
st,_,b=api.req('PUT','/api/admin/users/kc.user/password',{'password':'a-brand-new-password-1'},A); check('agent sets a new password', st==204, b)
v=Client(); st,_,b=v.req('POST','/api/firstfactor',{'username':'kc.user','password':'test-pass-123'}); check('old password refused', st==401)
v=Client(); st,_,b=v.req('POST','/api/firstfactor',{'username':'KC.USER','password':'a-brand-new-password-1'}); check('new password accepted, username any case', st==200, b)
st,_,b=api.req('DELETE','/api/admin/users/kc.user',None,A); check('agent deletes user', st==204, b)
v=Client(); st,_,b=v.req('POST','/api/firstfactor',{'username':'kc.user','password':'a-brand-new-password-1'}); check('deleted user cannot log in', st==401)
st,_,b=api.req('POST','/api/admin/users',{'username':'kc.user','email':'other@example.com'},A); check('deleted username never reused', st==409, b)
st,_,b=api.req('GET','/api/admin/users',None,{'Authorization':'Bearer '+t['access_token']}); check('user token refused by admin API', st in (401,403), b[:100])
st,_,b=api.req('GET','/api/admin/users',None,{}); check('session-less request refused', st==401)
st,_,b=u.req('GET','/api/admin/users'); check('browser session refused by admin API', st==401)
print(f'{sum(results)}/{len(results)} passed')
