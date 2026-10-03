export function parseEmails(value=''){ return value.split(',').map(x=>x.trim().toLowerCase()).filter(Boolean); }
export function isAdminEmail(email, allowlist){ return parseEmails(allowlist).includes(String(email||'').toLowerCase()); }
export function requireTenant(session){ if(!session?.tenantId) throw new Error('TENANT_REQUIRED'); return session.tenantId; }
export function hasEntitlement(entitlements, capabilityId){ return entitlements.some(e=>e.capabilityId===capabilityId && e.status==='ACTIVE'); }
export function assertEntitled(entitlements, capabilityId){ if(!hasEntitlement(entitlements,capabilityId)){ const e=new Error('CAPABILITY_NOT_ENTITLED'); e.code='CAPABILITY_NOT_ENTITLED'; throw e; } }
