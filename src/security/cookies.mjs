export function serializeCookie(name,value,{maxAge=28800,path='/',secure=true,httpOnly=true,sameSite='Lax'}={}){
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=${path}; ${secure?'Secure; ':''}${httpOnly?'HttpOnly; ':''}SameSite=${sameSite}`;
}
export function getCookie(request,name){ const raw=request.headers.get('Cookie')||''; const pair=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(`${name}=`)); return pair?decodeURIComponent(pair.slice(name.length+1)):null; }
