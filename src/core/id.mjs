export function id(prefix='id') { return `${prefix}_${crypto.randomUUID().replaceAll('-','').slice(0,18)}`; }
export function nowIso(){ return new Date().toISOString(); }
