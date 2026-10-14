import{getStore}from'@netlify/blobs';
import{randomBytes,scryptSync,timingSafeEqual,createHash}from'node:crypto';

const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json'}}),
E=(m,s=400)=>J({e:m},s),
nk=n=>'u/'+String(n).toLowerCase(),
th=t=>createHash('sha256').update(String(t)).digest('hex'),
hp=(p,s)=>scryptSync(p,s,32).toString('hex'),
eq=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&timingSafeEqual(a,b)},
isOwner=k=>!!process.env.OWNER_KEY&&typeof k==='string'&&eq(k,process.env.OWNER_KEY),
okp=p=>typeof p==='string'&&p.length<30000&&/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]*$/.test(p),
cl=d=>{if(!d||typeof d!=='object'||JSON.stringify(d).length>3e6)return{};d.coins=Math.max(0,Math.floor(+d.coins)||0);return d},
AB='ABCDEFGHJKLMNPQRSTUVWXYZ23456789',
gen=()=>[...randomBytes(24)].map(x=>AB[x%32]).join('');

/* leer-modificar-escribir con reintento (no pisa cambios simultáneos) */
const upd=async(s,key,fn)=>{
  for(let i=0;i<6;i++){
    const r=await s.getWithMetadata(key,{type:'json'});
    if(!r)return{err:'Sesión inválida'};
    const out=await fn(r.data);
    if(out&&out.err)return out;
    const w=await s.setJSON(key,r.data,{onlyIfMatch:r.etag});
    if(!w||w.modified!==false)return out||{};
  }
  return{err:'Intenta de nuevo'};
};

export default async req=>{
  if(req.method!=='POST')return E('Método no permitido',405);
  let b;try{b=await req.json()}catch{return E('Datos inválidos')}
  if(!b||typeof b!=='object')return E('Datos inválidos');
  const s=getStore({name:'ruleta',consistency:'strong'}),a=b.a,
    ok=u=>Array.isArray(u.tk)&&u.tk.includes(th(b.k)),
    res=r=>E(r.err,r.err==='Sesión inválida'?401:400);

  /* crear cuenta (nombre real = privado; nombre de perfil + foto = público) */
  if(a==='reg'){
    if(!/^\w{3,16}$/.test(b.n||'')||typeof b.pw!=='string'||b.pw.length<6||typeof b.r!=='string'||!b.r.trim()||b.r.length>30)return E('Datos incompletos o inválidos');
    if(await s.get(nk(b.n)))return E('Ese nombre ya está en uso');
    const k=randomBytes(24).toString('hex'),sl=randomBytes(16).toString('hex'),
      u={n:b.n,r:b.r.trim(),s:sl,h:hp(b.pw,sl),p:okp(b.p)?b.p:'',d:cl(b.d),g:0,tk:[th(k)]};
    const w=await s.setJSON(nk(b.n),u,{onlyIfNew:true});
    if(w&&w.modified===false)return E('Ese nombre ya está en uso');
    return J({n:u.n,k,p:u.p,r:u.r});
  }

  /* entrar desde cualquier celular: devuelve todo lo guardado */
  if(a==='login'){
    const u=await s.get(nk(b.n||''),{type:'json'});
    if(!u||typeof b.pw!=='string'||!eq(hp(b.pw,u.s),u.h))return E('Nombre o contraseña incorrectos',401);
    const k=randomBytes(24).toString('hex');let d;
    const r=await upd(s,nk(u.n),x=>{x.tk=[...x.tk.slice(-7),th(k)];x.d=x.d||{};x.d.coins=(x.d.coins|0)+(x.g|0);x.g=0;d=x.d;return{n:x.n,r:x.r,p:x.p}});
    return r.err?res(r):J({...r,k,d});
  }

  /* guardar en la nube / recuperar al abrir */
  if(a==='save'||a==='me'){
    let o;
    const r=await upd(s,nk(b.n||''),x=>{
      if(!ok(x))return{err:'Sesión inválida'};
      if(a==='save'){x.d=cl(b.d);if(okp(b.p))x.p=b.p;o={g:x.g|0};x.g=0}
      else{x.d=x.d||{};x.d.coins=(x.d.coins|0)+(x.g|0);x.g=0;o={d:x.d,p:x.p}}
    });
    return r.err?res(r):J(o);
  }

  /* buscar: solo nombre y foto son públicos */
  if(a==='find'){
    const q=String(b.q||'').toLowerCase().replace(/\W/g,'').slice(0,16),{blobs}=await s.list({prefix:'u/'+q});
    const u=(await Promise.all(blobs.slice(0,30).map(x=>s.get(x.key,{type:'json'})))).filter(Boolean).map(x=>({n:x.n,p:x.p}));
    return J({u});
  }

  /* regalar: se descuenta en el servidor; si no alcanza, no pasa */
  if(a==='gift'){
    const amt=Math.floor(+b.amt),to=String(b.to||'');
    if(!(amt>=1)||amt>1e9)return E('Cantidad inválida');
    if(to.toLowerCase()===String(b.n||'').toLowerCase())return E('No puedes regalarte a ti mismo');
    if(!await s.get(nk(to)))return E('Esa persona no existe');
    const r=await upd(s,nk(b.n||''),x=>{
      if(!ok(x))return{err:'Sesión inválida'};
      x.d=x.d||{};const c=(x.d.coins|0);
      if(c<amt)return{err:'No te alcanzan las monedas'};
      x.d.coins=c-amt;return{c:x.d.coins};
    });
    if(r.err)return res(r);
    const t=await upd(s,nk(to),x=>{x.g=(x.g|0)+amt});
    if(t.err){await upd(s,nk(b.n),x=>{x.d.coins=(x.d.coins|0)+amt});return E('No se pudo enviar, intenta de nuevo')}
    return J({c:r.c});
  }

  /* dueño: el código secreto vive en la variable OWNER_KEY de Netlify */
  if(a==='own')return isOwner(b.key)?J({ok:1}):E('Código incorrecto',403);

  if(a==='mk'){
    if(!isOwner(b.key))return E('No autorizado',403);
    const v=Math.floor(+b.v);if(!(v>=1)||v>1e8)return E('Cantidad inválida');
    const c=gen();await s.setJSON('c/'+c,{v,t:Date.now()});
    return J({code:c.match(/.{4}/g).join('-')});
  }

  /* canjear: un solo uso, a la primera persona que lo use */
  if(a==='use'){
    const u=await s.get(nk(b.n||''),{type:'json'});
    if(!u||!ok(u))return E('Sesión inválida',401);
    const c=String(b.code||'').toUpperCase().replace(/[^A-Z0-9]/g,'');
    if(c.length!==24)return E('Código inválido');
    const g=await s.get('c/'+c,{type:'json'});
    if(!g||await s.get('x/'+c))return E('Código inválido o ya usado');
    const w=await s.setJSON('x/'+c,{by:u.n,t:Date.now()},{onlyIfNew:true});
    if(w&&w.modified===false)return E('Código inválido o ya usado');
    const r=await upd(s,nk(u.n),x=>{x.d=x.d||{};x.d.coins=(x.d.coins|0)+g.v;return{c:x.d.coins,v:g.v}});
    if(r.err){await s.delete('x/'+c);return res(r)}
    await s.delete('c/'+c);
    return J(r);
  }

  return E('Acción desconocida');
};

export const config={path:'/api'};
