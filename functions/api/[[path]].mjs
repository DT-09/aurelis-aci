import { evaluateEvent, simulatePolicy } from '../../src/core/control-engine.mjs';
import { CAPABILITIES } from '../../src/core/constants.mjs';
import { id, nowIso } from '../../src/core/id.mjs';
import { mapProblem } from '../../src/core/problem-mapping.mjs';
import { isAdminEmail, hasEntitlement } from '../../src/security/authorization.mjs';
import { getCookie, serializeCookie } from '../../src/security/cookies.mjs';

const json = (data,status=200,headers={}) => new Response(JSON.stringify(data,null,2),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers}});
const redirect = (url,status=302,extraHeaders={}) => new Response(null,{status,headers:{Location:url,...extraHeaders}});
const text = async req => { try { return await req.json(); } catch { return {}; } };
const dbRequired = env => { if(!env.DB) throw new Error('D1 binding DB is not configured.'); return env.DB; };
const sha256 = async value => { const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)); return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join(''); };
const randomToken = () => crypto.randomUUID()+crypto.randomUUID();

async function audit(env, actorType, actorId, tenantId, action, targetType='', targetId='', metadata={}) {
  try { await dbRequired(env).prepare('INSERT INTO audit_log (id,actor_type,actor_id,tenant_id,action,target_type,target_id,metadata_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)').bind(id('aud'),actorType,actorId||null,tenantId||null,action,targetType||null,targetId||null,JSON.stringify(metadata),nowIso()).run(); } catch {}
}

async function sessionFromRequest(request,env){
  const sid=getCookie(request,'aurelis_session'); if(!sid) return null;
  const db=dbRequired(env); const row=await db.prepare('SELECT s.*,u.email,u.name,u.role,u.tenant_id as user_tenant_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?').bind(sid,nowIso()).first();
  return row||null;
}
async function requireClient(request,env){ const s=await sessionFromRequest(request,env); if(!s||s.kind!=='CLIENT') throw Object.assign(new Error('AUTH_REQUIRED'),{status:401}); return s; }
async function requireAdmin(request,env){ const s=await sessionFromRequest(request,env); if(!s||s.kind!=='ADMIN'||s.role!=='SUPER_ADMIN') throw Object.assign(new Error('ADMIN_REQUIRED'),{status:403}); return s; }
async function entitlements(env,tenantId){ const rows=await dbRequired(env).prepare('SELECT * FROM entitlements WHERE tenant_id=? AND status=\'ACTIVE\'').bind(tenantId).all(); return rows.results||[]; }
async function ensureCapability(s,env,capability){ const es=await entitlements(env,s.tenant_id); if(!hasEntitlement(es,capability)) throw Object.assign(new Error('CAPABILITY_NOT_ENTITLED'),{status:403}); return es; }

async function googleStart(request,env){
  if(!env.GOOGLE_CLIENT_ID||!env.GOOGLE_REDIRECT_URI) return json({error:'GOOGLE_OAUTH_NOT_CONFIGURED'},503);
  const state=randomToken();
  const u=new URL('https://accounts.google.com/o/oauth2/v2/auth');
  u.searchParams.set('client_id',env.GOOGLE_CLIENT_ID); u.searchParams.set('redirect_uri',env.GOOGLE_REDIRECT_URI); u.searchParams.set('response_type','code'); u.searchParams.set('scope','openid email profile'); u.searchParams.set('state',state); u.searchParams.set('access_type','online');
  return redirect(u.toString(),302,{'Set-Cookie':serializeCookie('aurelis_oauth_state',state,{maxAge:600})});
}
async function googleCallback(request,env){
  const url=new URL(request.url); const code=url.searchParams.get('code'); const returnedState=url.searchParams.get('state'); const cookieState=getCookie(request,'aurelis_oauth_state'); if(!returnedState || !cookieState || returnedState!==cookieState) return redirect('/admin.html?error=oauth_state'); if(!code) return redirect('/admin.html?error=oauth_cancelled');
  const tokenResp=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code,client_id:env.GOOGLE_CLIENT_ID,client_secret:env.GOOGLE_CLIENT_SECRET,redirect_uri:env.GOOGLE_REDIRECT_URI,grant_type:'authorization_code'})});
  if(!tokenResp.ok) return redirect('/admin.html?error=oauth_token'); const token=await tokenResp.json();
  const userResp=await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{Authorization:`Bearer ${token.access_token}`}}); if(!userResp.ok) return redirect('/admin.html?error=oauth_user'); const g=await userResp.json();
  if(!isAdminEmail(g.email,env.ADMIN_EMAILS)) return redirect('/admin.html?error=not_authorized');
  const db=dbRequired(env); let u=await db.prepare('SELECT * FROM users WHERE email=?').bind(g.email.toLowerCase()).first();
  if(!u){ const uid=id('usr'); await db.prepare('INSERT INTO users (id,email,name,role,created_at) VALUES (?,?,?,?,?)').bind(uid,g.email.toLowerCase(),g.name||g.email,'SUPER_ADMIN',nowIso()).run(); u={id:uid,email:g.email.toLowerCase(),name:g.name||g.email,role:'SUPER_ADMIN'}; }
  const sid=id('ses'); const expires=new Date(Date.now()+Number(env.SESSION_TTL_SECONDS||28800)*1000).toISOString(); await db.prepare('INSERT INTO sessions (id,user_id,tenant_id,kind,expires_at,created_at) VALUES (?,?,?,?,?,?)').bind(sid,u.id,null,'ADMIN',expires,nowIso()).run();
  await audit(env,'ADMIN',u.id,null,'ADMIN_LOGIN');
  return redirect('/admin.html',302,{ 'Set-Cookie': serializeCookie('aurelis_session',sid,{maxAge:Number(env.SESSION_TTL_SECONDS||28800)}) });
}

async function clientInviteAccept(request,env){
  const body=await text(request); const token=body.token||new URL(request.url).searchParams.get('token'); if(!token) return json({error:'INVITATION_TOKEN_REQUIRED'},400);
  const db=dbRequired(env); const hash=await sha256(token); const inv=await db.prepare('SELECT * FROM invitations WHERE token_hash=? AND used_at IS NULL AND expires_at>?').bind(hash,nowIso()).first(); if(!inv) return json({error:'INVITATION_INVALID_OR_EXPIRED'},400);
  if(!body.name) return json({error:'NAME_REQUIRED'},400); const email=inv.email.toLowerCase();
  let u=await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first(); if(!u){ const uid=id('usr'); await db.prepare('INSERT INTO users (id,tenant_id,email,name,role,created_at) VALUES (?,?,?,?,?,?)').bind(uid,inv.tenant_id,email,body.name,'ADMIN',nowIso()).run(); u={id:uid,tenant_id:inv.tenant_id,email,name:body.name,role:'ADMIN'}; }
  await db.prepare('UPDATE invitations SET used_at=? WHERE id=?').bind(nowIso(),inv.id).run();
  const sid=id('ses'); const expires=new Date(Date.now()+Number(env.SESSION_TTL_SECONDS||28800)*1000).toISOString(); await db.prepare('INSERT INTO sessions (id,user_id,tenant_id,kind,expires_at,created_at) VALUES (?,?,?,?,?,?)').bind(sid,u.id,inv.tenant_id,'CLIENT',expires,nowIso()).run(); await audit(env,'USER',u.id,inv.tenant_id,'CLIENT_LOGIN');
  return json({ok:true},200,{'Set-Cookie':serializeCookie('aurelis_session',sid,{maxAge:Number(env.SESSION_TTL_SECONDS||28800)})});
}


async function demoEvaluate(request){ const body=await text(request); return json(evaluateEvent(body)); }

async function clientMe(request,env){ const s=await requireClient(request,env); const es=await entitlements(env,s.tenant_id); return json({user:{email:s.email,name:s.name,role:s.role},tenantId:s.tenant_id,entitlements:es}); }
async function clientOverview(request,env){ const s=await requireClient(request,env); const db=dbRequired(env); const tenant=s.tenant_id; const [assets,events,findings,evidence,changes]=await Promise.all([
  db.prepare('SELECT * FROM assets WHERE tenant_id=? ORDER BY updated_at DESC').bind(tenant).all(),
  db.prepare('SELECT * FROM events WHERE tenant_id=? ORDER BY created_at DESC LIMIT 20').bind(tenant).all(),
  db.prepare("SELECT * FROM findings WHERE tenant_id=? AND status!='RESOLVED' ORDER BY updated_at DESC").bind(tenant).all(),
  db.prepare('SELECT * FROM evidence WHERE tenant_id=? ORDER BY created_at DESC LIMIT 20').bind(tenant).all(),
  db.prepare('SELECT * FROM changes WHERE tenant_id=? ORDER BY created_at DESC LIMIT 20').bind(tenant).all()
]); return json({assets:assets.results||[],events:events.results||[],findings:findings.results||[],evidence:evidence.results||[],changes:changes.results||[]}); }
async function clientCapabilities(request,env){ const s=await requireClient(request,env); const es=await entitlements(env,s.tenant_id); return json({catalog:CAPABILITIES.map(c=>({...c,entitled:es.some(e=>e.capability_id===c.id)}))}); }
async function clientEvent(request,env){ const s=await requireClient(request,env); const body=await text(request); const es=await entitlements(env,s.tenant_id); if(!es.length) throw Object.assign(new Error('NO_ACTIVE_CAPABILITY'),{status:403}); if(body.capabilityId) await ensureCapability(s,env,body.capabilityId); const db=dbRequired(env); const eventId=id('evt'); const event={id:eventId,dataSensitivity:body.dataSensitivity||'INTERNAL',destinationTrust:body.destinationTrust||'INTERNAL',actionSeverity:body.actionSeverity||'MATERIAL',identityStatus:body.identityStatus||'KNOWN',approval:body.approval||'NONE',vendorRisk:body.vendorRisk||'LOW',changeDetected:Boolean(body.changeDetected)}; const evType=body.type||'CONTROL_EVENT'; await db.prepare('INSERT INTO events (id,tenant_id,type,severity,context_json,created_at) VALUES (?,?,?,?,?,?)').bind(eventId,s.tenant_id,evType,event.actionSeverity==='CONSEQUENTIAL'?'HIGH':'MEDIUM',JSON.stringify(event),nowIso()).run(); const result=evaluateEvent(event); const decisionId=id('dec'); await db.prepare('INSERT INTO decisions (id,tenant_id,event_id,decision,action,risk_score,risk_level,reasons_json,engine_version,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(decisionId,s.tenant_id,eventId,result.decision,result.action,result.risk.score,result.risk.level,JSON.stringify(result.reasons),result.engineVersion,nowIso()).run(); const actionId=id('act'); await db.prepare('INSERT INTO actions (id,tenant_id,decision_id,type,status,result_json,created_at) VALUES (?,?,?,?,?,?,?)').bind(actionId,s.tenant_id,decisionId,result.action,result.action==='BLOCK'?'COMPLETED':'RECORDED',JSON.stringify({result}),nowIso()).run(); const payload={event,result,decisionId,actionId}; const integrity=await sha256(JSON.stringify(payload)); const evidenceId=id('evd'); await db.prepare('INSERT INTO evidence (id,tenant_id,event_id,decision_id,action_id,type,payload_json,integrity_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?)').bind(evidenceId,s.tenant_id,eventId,decisionId,actionId,'CONTROL_DECISION',JSON.stringify(payload),integrity,nowIso()).run(); await audit(env,'USER',s.user_id,s.tenant_id,'CONTROL_EVALUATED','decision',decisionId,{eventId}); return json({eventId,decisionId,actionId,evidenceId,result}); }
async function clientProblem(request,env){ const s=await requireClient(request,env); const body=await text(request); const mapped=mapProblem(body.problem||''); const db=dbRequired(env); const pid=id('prb'); await db.prepare('INSERT INTO problem_requests (id,tenant_id,problem,desired_outcome,urgency,affected_systems,status,created_at) VALUES (?,?,?,?,?,?,?,?)').bind(pid,s.tenant_id,body.problem||'',body.desiredOutcome||'',body.urgency||'MEDIUM',body.affectedSystems||'', 'OPEN',nowIso()).run(); return json({id:pid,mappedCapabilities:mapped}); }
async function clientControlRequest(request,env){ const s=await requireClient(request,env); const body=await text(request); const db=dbRequired(env); const rid=id('ctl'); await db.prepare('INSERT INTO control_requests (id,tenant_id,problem,urgency,affected_assets,requested_outcome,status,created_at) VALUES (?,?,?,?,?,?,?,?)').bind(rid,s.tenant_id,body.problem||'',body.urgency||'MEDIUM',body.affectedAssets||'',body.requestedOutcome||'','OPEN',nowIso()).run(); await audit(env,'USER',s.user_id,s.tenant_id,'CONTROL_REQUEST_CREATED','control_request',rid); return json({id:rid,status:'OPEN'}); }
async function clientSimulate(request,env){ const s=await requireClient(request,env); await ensureCapability(s,env,'ai-assurance'); const body=await text(request); return json({results:simulatePolicy(body.events||[],body.policy||{blockExternalRestricted:true})}); }
async function clientAssetsCreate(request,env){ const s=await requireClient(request,env); const body=await text(request); const db=dbRequired(env); const aid=id('ast'); const t=body.type||'AI_AGENT'; const now=nowIso(); await db.prepare('INSERT INTO assets (id,tenant_id,type,name,owner,state,risk_level,metadata_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(aid,s.tenant_id,t,body.name||'Unnamed AI asset',body.owner||null,body.state||'DISCOVERED',body.riskLevel||'LOW',JSON.stringify(body.metadata||{}),now,now).run(); return json({id:aid}); }
async function clientPolicies(request,env){ const s=await requireClient(request,env); const db=dbRequired(env); if(request.method==='GET'){const r=await db.prepare('SELECT * FROM policies WHERE tenant_id=? ORDER BY updated_at DESC').bind(s.tenant_id).all();return json(r.results||[]);} const body=await text(request); const pid=id('pol'); const now=nowIso(); const definition=body.definition||{blockExternalRestricted:true}; await db.prepare('INSERT INTO policies (id,tenant_id,name,status,definition_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)').bind(pid,s.tenant_id,body.name||'Untitled Policy','ACTIVE',JSON.stringify(definition),now,now).run(); await db.prepare('INSERT INTO policy_versions (id,policy_id,version,definition_json,created_at) VALUES (?,?,?,?,?)').bind(id('pv'),pid,1,JSON.stringify(definition),now).run(); return json({id:pid,name:body.name||'Untitled Policy'}); }
async function clientGraph(request,env){ const s=await requireClient(request,env); const db=dbRequired(env); const r=await db.prepare('SELECT ar.*,a.name as from_label,a.type as from_type,b.name as to_label,b.type as to_type FROM asset_relationships ar JOIN assets a ON a.id=ar.from_id JOIN assets b ON b.id=ar.to_id WHERE ar.tenant_id=? ORDER BY ar.created_at DESC').bind(s.tenant_id).all(); return json(r.results||[]); }
async function clientRelationship(request,env){ const s=await requireClient(request,env); const body=await text(request); const db=dbRequired(env); const exists=await db.prepare('SELECT id FROM assets WHERE id IN (?,?) AND tenant_id=?').bind(body.fromId,body.toId,s.tenant_id).all(); if((exists.results||[]).length!==2)return json({error:'ASSET_NOT_FOUND'},404); const rid=id('rel'); await db.prepare('INSERT INTO asset_relationships (id,tenant_id,from_id,to_id,relationship,created_at) VALUES (?,?,?,?,?,?)').bind(rid,s.tenant_id,body.fromId,body.toId,body.relationship||'RELATED_TO',nowIso()).run(); return json({id:rid}); }
async function clientChanges(request,env){ const s=await requireClient(request,env); const db=dbRequired(env); const r=await db.prepare('SELECT * FROM changes WHERE tenant_id=? ORDER BY created_at DESC LIMIT 100').bind(s.tenant_id).all(); return json(r.results||[]); }
async function clientInvestigations(request,env){ const s=await requireClient(request,env); const db=dbRequired(env); if(request.method==='GET'){const r=await db.prepare('SELECT * FROM investigations WHERE tenant_id=? ORDER BY updated_at DESC').bind(s.tenant_id).all();return json(r.results||[]);} const body=await text(request); const iid=id('invst'); const now=nowIso(); await db.prepare('INSERT INTO investigations (id,tenant_id,event_id,title,state,summary,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)').bind(iid,s.tenant_id,body.eventId||null,body.title||'Investigation','DETECTED',body.summary||'',now,now).run(); return json({id:iid}); }
async function clientReadiness(request,env){ const s=await requireClient(request,env); const db=dbRequired(env); const [a,e,p,f]=await Promise.all([db.prepare('SELECT COUNT(*) c FROM assets WHERE tenant_id=?').bind(s.tenant_id).first(),db.prepare('SELECT COUNT(*) c FROM evidence WHERE tenant_id=?').bind(s.tenant_id).first(),db.prepare('SELECT COUNT(*) c FROM policies WHERE tenant_id=? AND status=\'ACTIVE\'').bind(s.tenant_id).first(),db.prepare("SELECT COUNT(*) c FROM findings WHERE tenant_id=? AND status!='RESOLVED'").bind(s.tenant_id).first()]); const checks=[{name:'AI asset inventory',status:Number(a?.c||0)>0?'PASS':'WARNING'},{name:'Evidence coverage',status:Number(e?.c||0)>0?'PASS':'WARNING'},{name:'Active policies',status:Number(p?.c||0)>0?'PASS':'WARNING'},{name:'Unresolved findings',status:Number(f?.c||0)===0?'PASS':'CONDITIONAL'}]; return json({checks,overall:checks.some(x=>x.status==='CONDITIONAL')?'CONDITIONAL':checks.every(x=>x.status==='PASS')?'PASS':'WARNING'}); }
async function clientApiKeys(request,env){ const s=await requireClient(request,env); const db=dbRequired(env); if(request.method==='GET'){const r=await db.prepare('SELECT id,name,scopes_json,status,created_at,last_used_at FROM api_keys WHERE tenant_id=? ORDER BY created_at DESC').bind(s.tenant_id).all();return json(r.results||[]);} const body=await text(request); const raw='aurelis_'+crypto.randomUUID().replaceAll('-',''); const hash=await sha256(raw); const kid=id('key'); await db.prepare('INSERT INTO api_keys (id,tenant_id,name,key_hash,scopes_json,status,created_at) VALUES (?,?,?,?,?,?,?)').bind(kid,s.tenant_id,body.name||'API credential',hash,JSON.stringify(body.scopes||['events:write']), 'ACTIVE',nowIso()).run(); return json({id:kid,key:raw,warning:'Store this credential now. Aurelis will not display the secret again.'}); }
async function clientAssets(request,env){ const s=await requireClient(request,env); const db=dbRequired(env); const r=await db.prepare('SELECT * FROM assets WHERE tenant_id=? ORDER BY updated_at DESC').bind(s.tenant_id).all(); return json(r.results||[]); }
async function clientEvidence(request,env){ const s=await requireClient(request,env); const db=dbRequired(env); const r=await db.prepare('SELECT * FROM evidence WHERE tenant_id=? ORDER BY created_at DESC LIMIT 100').bind(s.tenant_id).all(); return json(r.results||[]); }
async function clientRemediation(request,env){ const s=await requireClient(request,env); const body=await text(request); const db=dbRequired(env); if(request.method==='GET'){const r=await db.prepare('SELECT * FROM remediation_tasks WHERE tenant_id=? ORDER BY updated_at DESC').bind(s.tenant_id).all();return json(r.results||[]);} const task=id('rem'); await db.prepare('INSERT INTO remediation_tasks (id,tenant_id,finding_id,status,owner,due_at,notes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)').bind(task,s.tenant_id,body.findingId,'OPEN',body.owner||null,body.dueAt||null,body.notes||'',nowIso(),nowIso()).run(); return json({id:task,status:'OPEN'}); }
async function clientRetest(request,env){ const s=await requireClient(request,env); const body=await text(request); const db=dbRequired(env); const finding=await db.prepare('SELECT * FROM findings WHERE id=? AND tenant_id=?').bind(body.findingId,s.tenant_id).first(); if(!finding) return json({error:'FINDING_NOT_FOUND'},404); const pass=body.result==='PASS'; const rid=id('rtt'); await db.prepare('INSERT INTO retests (id,tenant_id,finding_id,result,details_json,created_at) VALUES (?,?,?,?,?,?)').bind(rid,s.tenant_id,finding.id,pass?'PASS':'FAIL',JSON.stringify(body.details||{}),nowIso()).run(); if(pass) await db.prepare('UPDATE findings SET status=\'RESOLVED\',updated_at=? WHERE id=? AND tenant_id=?').bind(nowIso(),finding.id,s.tenant_id).run(); return json({id:rid,result:pass?'PASS':'FAIL'}); }

async function adminMe(request,env){ const s=await requireAdmin(request,env); return json({email:s.email,name:s.name,role:s.role}); }
async function adminTenants(request,env){ await requireAdmin(request,env); const db=dbRequired(env); if(request.method==='GET'){const r=await db.prepare('SELECT * FROM tenants ORDER BY created_at DESC').all();return json(r.results||[]);} const body=await text(request); const tenant=id('ten'); await db.prepare('INSERT INTO tenants (id,name,status,created_at) VALUES (?,?,?,?)').bind(tenant,body.name,'ACTIVE',nowIso()).run(); for(const c of body.capabilities||[]) await db.prepare('INSERT INTO entitlements (id,tenant_id,capability_id,status,granted_at) VALUES (?,?,?,?,?)').bind(id('ent'),tenant,c,'ACTIVE',nowIso()).run(); return json({id:tenant,name:body.name}); }
async function adminEntitlements(request,env){ const s=await requireAdmin(request,env); const db=dbRequired(env); const body=await text(request); if(request.method==='GET'){const r=await db.prepare('SELECT * FROM entitlements ORDER BY granted_at DESC').all();return json(r.results||[]);} await db.prepare('INSERT INTO entitlements (id,tenant_id,capability_id,status,granted_at) VALUES (?,?,?,?,?) ON CONFLICT(tenant_id,capability_id) DO UPDATE SET status=excluded.status').bind(id('ent'),body.tenantId,body.capabilityId,body.status||'ACTIVE',nowIso()).run(); await audit(env,'ADMIN',s.user_id,body.tenantId,'ENTITLEMENT_CHANGED','capability',body.capabilityId); return json({ok:true}); }
async function adminInvitation(request,env){ const s=await requireAdmin(request,env); const body=await text(request); const token=randomToken(); const hash=await sha256(token); const invitationId=id('inv'); const expires=new Date(Date.now()+24*3600*1000).toISOString(); const db=dbRequired(env); await db.prepare('INSERT INTO invitations (id,tenant_id,email,token_hash,expires_at,created_at) VALUES (?,?,?,?,?,?)').bind(invitationId,body.tenantId,body.email.toLowerCase(),hash,expires,nowIso()).run(); await audit(env,'ADMIN',s.user_id,body.tenantId,'INVITATION_CREATED','invitation',invitationId); return json({id:invitationId,inviteUrl:`${new URL(request.url).origin}/access.html?invite=${encodeURIComponent(token)}`,expiresAt:expires}); }
async function adminControlRequests(request,env){ await requireAdmin(request,env); const db=dbRequired(env); const r=await db.prepare('SELECT * FROM control_requests ORDER BY created_at DESC LIMIT 100').all(); return json(r.results||[]); }
async function adminAudit(request,env){ await requireAdmin(request,env); const db=dbRequired(env); const r=await db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200').all(); return json(r.results||[]); }
async function adminSystem(request,env){ await requireAdmin(request,env); const db=dbRequired(env); const checks=[]; try { await db.prepare('SELECT 1').first(); checks.push({name:'D1',status:'OK'}); } catch(e){checks.push({name:'D1',status:'ERROR',detail:e.message});} return json({environment:env.APP_ENV||'unknown',checks,capabilities:CAPABILITIES.length,engine:'1.0.0'}); }

export async function onRequest(context){
  const {request,env}=context; const path=new URL(request.url).pathname.replace(/^\/api\/?/,'').replace(/\/$/,'');
  try {
    if(path==='demo/evaluate' && request.method==='POST') return demoEvaluate(request);
    if(path==='auth/google') return googleStart(request,env);
    if(path==='auth/google/callback') return googleCallback(request,env);
    if(path==='auth/invite/accept' && request.method==='POST') return clientInviteAccept(request,env);
    if(path==='client/me') return clientMe(request,env);
    if(path==='client/overview') return clientOverview(request,env);
    if(path==='client/capabilities') return clientCapabilities(request,env);
    if(path==='client/event' && request.method==='POST') return clientEvent(request,env);
    if(path==='client/problem' && request.method==='POST') return clientProblem(request,env);
    if(path==='client/control-request' && request.method==='POST') return clientControlRequest(request,env);
    if(path==='client/policy-simulate' && request.method==='POST') return clientSimulate(request,env);
    if(path==='client/assets' && request.method==='POST') return clientAssetsCreate(request,env);
    if(path==='client/relationships' && request.method==='POST') return clientRelationship(request,env);
    if(path==='client/graph') return clientGraph(request,env);
    if(path==='client/assets') return clientAssets(request,env);
    if(path==='client/policies') return clientPolicies(request,env);
    if(path==='client/changes') return clientChanges(request,env);
    if(path==='client/investigations') return clientInvestigations(request,env);
    if(path==='client/readiness') return clientReadiness(request,env);
    if(path==='client/api-keys') return clientApiKeys(request,env);
    if(path==='client/evidence') return clientEvidence(request,env);
    if(path==='client/remediation') return clientRemediation(request,env);
    if(path==='client/retest' && request.method==='POST') return clientRetest(request,env);
    if(path==='admin/me') return adminMe(request,env);
    if(path==='admin/tenants') return adminTenants(request,env);
    if(path==='admin/entitlements') return adminEntitlements(request,env);
    if(path==='admin/invitations' && request.method==='POST') return adminInvitation(request,env);
    if(path==='admin/control-requests') return adminControlRequests(request,env);
    if(path==='admin/audit') return adminAudit(request,env);
    if(path==='admin/system') return adminSystem(request,env);
    return json({error:'NOT_FOUND'},404);
  } catch(e) { return json({error:e.message||'INTERNAL_ERROR',code:e.code||e.message||'INTERNAL_ERROR'},e.status||500); }
}
