export async function onRequest(context){
  const response=await context.next();
  const h=new Headers(response.headers);
  h.set('X-Content-Type-Options','nosniff');
  h.set('X-Frame-Options','DENY');
  h.set('Referrer-Policy','strict-origin-when-cross-origin');
  h.set('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  h.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  return new Response(response.body,{status:response.status,statusText:response.statusText,headers:h});
}
