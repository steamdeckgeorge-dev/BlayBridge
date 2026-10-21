const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'}});
async function authorised(request,env){
 const jwt=request.headers.get('Cf-Access-Jwt-Assertion');
 if(!jwt||!env.ACCESS_TEAM_DOMAIN||!env.ACCESS_AUD)return false;
 try{
 const [h,p,s]=jwt.split('.');if(!s)return false;
 const decode=x=>Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
 const header=JSON.parse(new TextDecoder().decode(decode(h))),payload=JSON.parse(new TextDecoder().decode(decode(p)));
 if(header.alg!=='RS256'||!header.kid||payload.iss!==`https://${env.ACCESS_TEAM_DOMAIN}`||!Array.isArray(payload.aud)||!payload.aud.includes(env.ACCESS_AUD)||!payload.exp||payload.exp<=Date.now()/1000||payload.nbf>Date.now()/1000)return false;
 const res=await fetch(`https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`,{cf:{cacheTtl:300,cacheEverything:true}});if(!res.ok)return false;
 const certs=await res.json();const jwk=(certs.keys||[]).find(k=>k.kid===header.kid&&k.kty==='RSA');if(!jwk)return false;
 const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 return await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,decode(s),new TextEncoder().encode(h+'.'+p));
 }catch{return false}
}
export async function onRequest({request,env,params}){
 if(!env.DB)return json({error:'Database not configured. Follow README.'},503);
 const path=(params.path||[]).join('/'),method=request.method;
 if(path==='posts'&&method==='GET'){
 const {results}=await env.DB.prepare("SELECT id,title,category,excerpt,body,source_url,updated_at FROM posts WHERE status='published' ORDER BY updated_at DESC LIMIT 100").all();return json({posts:results});
 }
 if(path==='ads'&&method==='GET'){
 const {results}=await env.DB.prepare("SELECT id,title,description,url,cta FROM personal_ads WHERE status='published' ORDER BY updated_at DESC LIMIT 12").all();return json({ads:results});
 }
 if(!await authorised(request,env))return json({error:'Unauthorised. Configure Cloudflare Access and log in.'},401);
 if(path==='admin/ads'&&method==='GET'){
 const {results}=await env.DB.prepare('SELECT * FROM personal_ads ORDER BY updated_at DESC LIMIT 100').all();return json({ads:results});
 }
 if(path==='admin/ads'&&method==='POST'){
 let d;try{d=await request.json()}catch{return json({error:'Invalid JSON'},400)}
 const title=String(d.title||'').trim(),description=String(d.description||'').trim(),url=String(d.url||'').trim(),cta=String(d.cta||'Learn more').trim(),status=d.status==='published'?'published':'draft';
 if(!title||title.length>120||!description||description.length>500||!/^https:\/\/[^\s]+$/i.test(url)||url.length>1000||!cta||cta.length>40)return json({error:'Enter a valid title, description, HTTPS link and button label.'},400);
 const id=typeof d.id==='string'&&/^[a-f0-9-]{36}$/.test(d.id)?d.id:crypto.randomUUID();
 await env.DB.prepare("INSERT INTO personal_ads (id,title,description,url,cta,status) VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,description=excluded.description,url=excluded.url,cta=excluded.cta,status=excluded.status,updated_at=datetime('now')").bind(id,title,description,url,cta,status).run();return json({ok:true,id});
 }
 if(path==='admin/ads/delete'&&method==='POST'){
 let d;try{d=await request.json()}catch{return json({error:'Invalid JSON'},400)}
 if(typeof d.id!=='string'||!/^[a-f0-9-]{36}$/.test(d.id))return json({error:'Invalid id'},400);
 await env.DB.prepare('DELETE FROM personal_ads WHERE id=?').bind(d.id).run();return json({ok:true});
 }
 if(path==='admin/posts'&&method==='GET'){
 const {results}=await env.DB.prepare('SELECT * FROM posts ORDER BY updated_at DESC LIMIT 200').all();return json({posts:results});
 }
 if(path==='admin/posts'&&method==='POST'){
 let data;try{data=await request.json()}catch{return json({error:'Invalid JSON'},400)}
 const title=String(data.title||'').trim(),category=String(data.category||'Technology').trim(),excerpt=String(data.excerpt||'').trim(),body=String(data.body||'').trim(),source=String(data.source_url||'').trim(),status=data.status==='published'?'published':'draft';
 if(!title||title.length>180||!body||body.length>30000||excerpt.length>500||category.length>80||source.length>1000|| (source&&!/^https:\/\//i.test(source)))return json({error:'Check title, body, excerpt, category and HTTPS source URL.'},400);
 const id=typeof data.id==='string'&&/^[a-f0-9-]{36}$/.test(data.id)?data.id:crypto.randomUUID();
 await env.DB.prepare('INSERT INTO posts (id,title,category,excerpt,body,source_url,status) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,category=excluded.category,excerpt=excluded.excerpt,body=excluded.body,source_url=excluded.source_url,status=excluded.status,updated_at=datetime(\'now\')').bind(id,title,category,excerpt,body,source,status).run();return json({ok:true,id});
 }
 if(path==='admin/delete'&&method==='POST'){
 let data;try{data=await request.json()}catch{return json({error:'Invalid JSON'},400)}
 if(typeof data.id!=='string'||!/^[a-f0-9-]{36}$/.test(data.id))return json({error:'Invalid id'},400);
 await env.DB.prepare('DELETE FROM posts WHERE id=?').bind(data.id).run();return json({ok:true});
 }
 if(path==='admin/import'&&method==='POST'){
 // Semi-automatic: fetch RSS/Atom feeds, create source-linked drafts; never publish without approval.
 const feeds=[{url:'https://www.nasa.gov/feed/',category:'Intelligent Insights'},{url:'https://blog.cloudflare.com/rss/',category:'Technology'}];let count=0;
 for(const feed of feeds){try{
 const r=await fetch(feed.url,{headers:{'user-agent':'BlayBridgeEditor/1.0'},signal:AbortSignal.timeout(7000)});if(!r.ok)continue;const xml=(await r.text()).slice(0,200000);
 const entries=[...xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>|<entry\b[^>]*>([\s\S]*?)<\/entry>/gi)].slice(0,8);
 for(const match of entries){const item=match[1]||match[2];const get=(tag)=>{const m=item.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`,'i'));return m?m[1].replace(/<!\[CDATA\[|\]\]>/g,'').replace(/<[^>]+>/g,'').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').trim():''};
 const title=get('title').slice(0,180);let link=get('link');if(!link){const m=item.match(/<link[^>]+href=["']([^"']+)/i);link=m?.[1]||''}if(!title||!/^https:\/\//i.test(link))continue;
 const id=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(link)).then(b=>[...new Uint8Array(b)].slice(0,16).map(x=>x.toString(16).padStart(2,'0')).join('')).then(x=>`${x.slice(0,8)}-${x.slice(8,12)}-4${x.slice(13,16)}-a${x.slice(17,20)}-${x.slice(20,32)}`);
 const description=get('description')||get('summary');const excerpt=description.slice(0,450);
 const result=await env.DB.prepare("INSERT OR IGNORE INTO posts (id,title,category,excerpt,body,source_url,status) VALUES (?,?,?,?,?,?,'draft')").bind(id,title,feed.category,excerpt,`SOURCE-BASED DRAFT — verify facts, write your own original explanation, and cite the source before publishing.\n\nOriginal headline: ${title}\n\nSource: ${link}`,link).run();count+=result.meta.changes||0;
 }
 }catch{ /* Unavailable source; try other feeds */ }}return json({ok:true,created:count,message:'Source-linked drafts imported for review. No articles published.'});
 }
 return json({error:'Not found'},404);
}
