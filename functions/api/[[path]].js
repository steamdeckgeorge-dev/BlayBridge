
const json = (value, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", "x-frame-options": "DENY", "permissions-policy": "camera=(), microphone=(), geolocation=()"
    }
  });

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    Math.ceil(base64.length / 4) * 4,
    "="
  );
  return Uint8Array.from(
    atob(padded),
    character => character.charCodeAt(0)
  );
}

function safeIssuer(value) {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      !url.hostname.endsWith(".cloudflareaccess.com")
    ) {
      return "UNEXPECTED_ISSUER";
    }
    return `${url.origin}${url.pathname}`;
  } catch {
    return "INVALID_ISSUER";
  }
}

async function checkAccess(request, env) {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) {
    return { diagnostic: "CONFIG_MISSING" };
  }

  const domain = String(env.ACCESS_TEAM_DOMAIN)
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/+$/, "");

  const audience = String(env.ACCESS_AUD).trim();

  let jwt = request.headers.get("Cf-Access-Jwt-Assertion");

  if (!jwt) {
    const cookie = (request.headers.get("Cookie") || "")
      .match(/(?:^|;\s*)CF_Authorization=([^;]+)/);

    if (cookie) {
      try {
        jwt = decodeURIComponent(cookie[1]);
      } catch {
        return { diagnostic: "COOKIE_INVALID" };
      }
    }
  }

  if (!jwt) {
    return { diagnostic: "TOKEN_MISSING" };
  }

  const parts = jwt.split(".");

  if (parts.length !== 3) {
    return { diagnostic: "TOKEN_MALFORMED" };
  }

  const [h, p, s] = parts;

  let header;
  let payload;

  try {
    header = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(h))
    );
    payload = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(p))
    );
  } catch {
    return { diagnostic: "TOKEN_MALFORMED" };
  }

  if (header.alg !== "RS256" || !header.kid) {
    return { diagnostic: "TOKEN_HEADER_INVALID" };
  }

  const expectedIssuer = `https://${domain}`;
  const actualIssuer = String(payload.iss || "")
    .replace(/\/+$/, "");

  if (actualIssuer !== expectedIssuer) {
    return {
      diagnostic: "ISSUER_MISMATCH",
      actual_issuer: safeIssuer(String(payload.iss || "")),
      expected_issuer: expectedIssuer
    };
  }

  const audiences = Array.isArray(payload.aud)
    ? payload.aud
    : [payload.aud];

  if (!audiences.includes(audience)) {
    return { diagnostic: "AUDIENCE_MISMATCH" };
  }

  const now = Math.floor(Date.now() / 1000);

  if (
    typeof payload.exp !== "number" ||
    payload.exp <= now ||
    (typeof payload.nbf === "number" && payload.nbf > now)
  ) {
    return { diagnostic: "TOKEN_EXPIRED_OR_NOT_YET_VALID" };
  }

  let response;

  try {
    response = await fetch(
      `https://${domain}/cdn-cgi/access/certs`,
      {
        cf: {
          cacheTtl: 300,
          cacheEverything: true
        }
      }
    );
  } catch {
    return { diagnostic: "CERT_FETCH_FAILED" };
  }

  if (!response.ok) {
    return { diagnostic: "CERT_FETCH_FAILED" };
  }

  let certs;

  try {
    certs = await response.json();
  } catch {
    return { diagnostic: "CERT_RESPONSE_INVALID" };
  }

  const jwk = (certs.keys || []).find(
    key => key.kid === header.kid && key.kty === "RSA"
  );

  if (!jwk) {
    return { diagnostic: "SIGNING_KEY_NOT_FOUND" };
  }

  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      decodeBase64Url(s),
      new TextEncoder().encode(`${h}.${p}`)
    );

    if (!valid) {
      return { diagnostic: "SIGNATURE_INVALID" };
    }
  } catch {
    return { diagnostic: "SIGNATURE_CHECK_FAILED" };
  }

  return null;
}

const validId = id =>
  typeof id === "string" &&
  /^[a-f0-9-]{36}$/.test(id);

async function bodyJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export async function onRequest({ request, env, params }) {
  if (!env.DB) {
    return json(
      { error: "Database not configured. Follow README." },
      503
    );
  }

  const path = (params.path || []).join("/");
  const method = request.method;

  const homeDefaults={eyebrow:"IDEAS WORTH EXPLORING",title:"Understand the world. Stay ahead of what\u0027s next.",description:"Clear thinking on technology, artificial intelligence, science, digital skills and the ideas shaping our future.",button:"Explore articles →"};
  if(path==="site-content"&&method==="GET"){const row=await env.DB.prepare("SELECT value FROM site_settings WHERE key=?").bind("homepage").first();let saved={};try{saved=JSON.parse(row?.value||"{}")}catch{}return json({...homeDefaults,...saved})}

  if(path==="tech-video"&&method==="GET"){if(!env.OFFERS_BUCKET)return json({error:"Video storage unavailable"},503);const obj=await env.OFFERS_BUCKET.get("site/tech-video");if(!obj)return json({error:"No animation uploaded"},404);return new Response(obj.body,{headers:{"content-type":obj.httpMetadata?.contentType||"video/mp4","cache-control":"public, max-age=300","x-content-type-options":"nosniff","accept-ranges":"none"}})}
  if(path==="tech-settings"&&method==="GET"){const row=await env.DB.prepare("SELECT value FROM site_settings WHERE key=?").bind("techAnimation").first();let saved={};try{saved=JSON.parse(row?.value||"{}")}catch{}return json({enabled:saved.enabled===true,heading:saved.heading||""})}
  if(path==="hero-image"&&method==="GET"){if(!env.OFFERS_BUCKET)return json({error:"Image storage unavailable"},503);const obj=await env.OFFERS_BUCKET.get("site/hero-image");if(!obj)return json({error:"No cover image"},404);return new Response(obj.body,{headers:{"content-type":obj.httpMetadata?.contentType||"image/jpeg","cache-control":"public, max-age=300","x-content-type-options":"nosniff"}})}
  if(path==="contact-content"&&method==="GET"){const row=await env.DB.prepare("SELECT value FROM site_settings WHERE key=?").bind("contact").first();let saved={};try{saved=JSON.parse(row?.value||"{}")}catch{}return json({content:saved})}
  if(path==="about-content"&&method==="GET"){const row=await env.DB.prepare("SELECT value FROM site_settings WHERE key=?").bind("about").first();let saved={};try{saved=JSON.parse(row?.value||"{}")}catch{}return json({content:saved})}
  if(path==="videos"&&method==="GET"){const {results}=await env.DB.prepare("SELECT youtube_id,title,description,category,url,cta,sponsored FROM media_videos WHERE status='published' ORDER BY updated_at DESC LIMIT 100").all();return json({videos:results.map(v=>({youtubeId:v.youtube_id,title:v.title,description:v.description,category:v.category,url:v.url,cta:v.cta,sponsored:!!v.sponsored}))})}
  if(path.startsWith("article-cover/")&&method==="GET"){const id=path.slice("article-cover/".length);if(!validId(id)||!env.OFFERS_BUCKET)return json({error:"Not found"},404);const row=await env.DB.prepare("SELECT p.status,s.value FROM posts p JOIN site_settings s ON s.key=('post-cover:'||p.id) WHERE p.id=?").bind(id).first();if(!row||row.status!=="published")return json({error:"Not found"},404);let cover={};try{cover=JSON.parse(row.value)}catch{}if(!["image","animation","custom"].includes(cover.type))return json({error:"Not found"},404);const obj=await env.OFFERS_BUCKET.get("article-covers/"+id);if(!obj)return json({error:"Not found"},404);return new Response(obj.body,{headers:{"content-type":obj.httpMetadata?.contentType||"application/octet-stream","cache-control":"public, max-age=300","x-content-type-options":"nosniff"}})}
  // PUBLIC ARTICLES
  if (path === "posts" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT p.id,p.title,p.category,p.excerpt,p.body,p.source_url,p.updated_at,s.value AS cover_json FROM posts p LEFT JOIN site_settings s ON s.key=('post-cover:'||p.id) WHERE p.status='published' ORDER BY p.updated_at DESC LIMIT 100"
    ).all();

    return json({ posts: results.map(p=>({...p,cover:JSON.parse(p.cover_json||'{}'),cover_json:undefined})) });
  }

  // PUBLIC ADVERTISEMENTS
  if (path === "ads" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id,title,description,url,cta,image_url FROM personal_ads WHERE status='published' ORDER BY updated_at DESC LIMIT 12"
    ).all();

    return json({ ads: results });
  }

  // PUBLIC OFFER IMAGES (only published offers)
  if (path.startsWith('offer-image/') && method === 'GET') {
    const id=path.slice('offer-image/'.length);
    if(!validId(id))return json({error:'Not found'},404);
    const row=await env.DB.prepare("SELECT image_url FROM personal_ads WHERE id=? AND status='published'").bind(id).first();
    if(!row||row.image_url!==('/api/offer-image/'+id)||!env.OFFERS_BUCKET)return json({error:'Not found'},404);
    const object=await env.OFFERS_BUCKET.get('offers/'+id);
    if(!object)return json({error:'Not found'},404);
    const type=object.httpMetadata?.contentType||'application/octet-stream';
    return new Response(object.body,{headers:{'content-type':type,'cache-control':'public, max-age=300','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; sandbox"}});
  }

  // Same-origin requirement for state-changing admin requests.
  if(path.startsWith("admin/") && !["GET","HEAD","OPTIONS"].includes(method)){
    const origin=request.headers.get("Origin");
    if(origin!==new URL(request.url).origin)return json({error:"Cross-origin admin request rejected"},403);
    const type=(request.headers.get("Content-Type")||"").toLowerCase();
    const upload=path.startsWith("admin/article-cover/")||path.startsWith("admin/ads/image/")||path==="admin/hero-image"||path==="admin/tech-video";
    const length=Number(request.headers.get("Content-Length")||0);
    if(length>((path==="admin/tech-video"||path.startsWith("admin/article-cover/"))?15*1024*1024:upload?6*1024*1024:256*1024))return json({error:"Request too large"},413);
    if(path==="admin/tech-video"&&!["video/mp4","video/webm"].includes(type))return json({error:"MP4 or WebM video required"},415);
    if(path==="admin/hero-image"&&!["image/jpeg","image/png","image/webp"].includes(type))return json({error:"JPG, PNG or WebP required"},415);
    if(path.startsWith("admin/article-cover/")&&!["image/jpeg","image/png","image/webp","video/mp4","video/webm"].includes(type))return json({error:"Upload JPG, PNG, WebP, MP4 or WebM"},415);
    if(!upload&&!type.startsWith("application/json"))return json({error:"JSON content type required"},415);
  }
  // ADMIN AUTHENTICATION
  const failure = await checkAccess(request, env);

  if (failure) {
    return json({
      error: "Unauthorised. Configure Cloudflare Access and log in.",
      diagnostic: "ACCESS_DENIED"
    }, 401);
  }

  if(path==="admin/contact-content"&&method==="GET"){const row=await env.DB.prepare("SELECT value FROM site_settings WHERE key=?").bind("contact").first();let saved={};try{saved=JSON.parse(row?.value||"{}")}catch{}return json({content:saved})}
  if(path==="admin/contact-content"&&method==="POST"){const d=await bodyJson(request);if(!d||typeof d!=="object")return json({error:"Invalid request"},400);const heading=String(d.heading||"").trim(),message=String(d.message||"").trim(),email=String(d.email||"").trim(),note=String(d.note||"").trim();if(!heading||heading.length>120||!message||message.length>2500||!note||note.length>1500||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254)return json({error:"Check contact heading, message, email and note."},400);await env.DB.prepare("INSERT INTO site_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind("contact",JSON.stringify({heading,message,email,note})).run();return json({ok:true})}
  if(path==="admin/about-content"&&method==="GET"){const row=await env.DB.prepare("SELECT value FROM site_settings WHERE key=?").bind("about").first();let saved={};try{saved=JSON.parse(row?.value||"{}")}catch{}return json({content:saved})}
  if(path==="admin/about-content"&&method==="POST"){const d=await bodyJson(request);if(!d||typeof d!=="object")return json({error:"Invalid request"},400);const limits={heading:120,intro:2500,mission:2500,editorial:2500,contact:2500},saved={};for(const [key,max] of Object.entries(limits)){if(typeof d[key]!=="string"||!d[key].trim()||d[key].length>max)return json({error:"Please provide "+key+" (maximum "+max+" characters)."},400);saved[key]=d[key].trim()}const pic=String(d.picture||"").trim();if(pic&&(!/^https:\/\/[^\s]+$/i.test(pic)||pic.length>1500))return json({error:"Picture must be an HTTPS image URL or blank."},400);saved.picture=pic;await env.DB.prepare("INSERT INTO site_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind("about",JSON.stringify(saved)).run();return json({ok:true})}
  if(path==="admin/tech-settings"&&method==="GET"){const row=await env.DB.prepare("SELECT value FROM site_settings WHERE key=?").bind("techAnimation").first();let saved={};try{saved=JSON.parse(row?.value||"{}")}catch{}return json({enabled:saved.enabled===true,heading:saved.heading||""})}
  if(path==="admin/tech-settings"&&method==="POST"){const d=await bodyJson(request);if(!d||typeof d.enabled!=="boolean"||typeof d.heading!=="string"||d.heading.length>100)return json({error:"Invalid animation settings"},400);await env.DB.prepare("INSERT INTO site_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind("techAnimation",JSON.stringify({enabled:d.enabled,heading:d.heading.trim()})).run();return json({ok:true})}
  if(path==="admin/tech-video"&&method==="POST"){if(!env.OFFERS_BUCKET)return json({error:"Video storage is not configured"},503);const type=(request.headers.get("Content-Type")||"").toLowerCase();if(!["video/mp4","video/webm"].includes(type))return json({error:"Use MP4 or WebM"},415);const bytes=await request.arrayBuffer();if(bytes.byteLength<100||bytes.byteLength>15*1024*1024)return json({error:"Video must be under 15 MB"},413);const b=new Uint8Array(bytes);const valid=type==="video/mp4"?String.fromCharCode(...b.slice(4,8))==="ftyp":String.fromCharCode(...b.slice(0,4))==="\x1aE\xdf\xa3";if(!valid)return json({error:"Invalid video file"},400);await env.OFFERS_BUCKET.put("site/tech-video",bytes,{httpMetadata:{contentType:type}});return json({ok:true})}
  if(path==="admin/hero-image"&&method==="POST"){if(!env.OFFERS_BUCKET)return json({error:"Image storage is not configured (OFFERS_BUCKET)."},503);const type=(request.headers.get("Content-Type")||"").toLowerCase();if(!["image/jpeg","image/png","image/webp"].includes(type))return json({error:"Upload a JPG, PNG or WebP image."},415);const bytes=await request.arrayBuffer();if(bytes.byteLength<100||bytes.byteLength>5*1024*1024)return json({error:"Image must be under 5 MB."},413);const b=new Uint8Array(bytes),valid=type==="image/png"?b[0]===137&&b[1]===80&&b[2]===78&&b[3]===71:type==="image/jpeg"?b[0]===255&&b[1]===216&&b[2]===255:b[0]===82&&b[1]===73&&b[2]===70&&b[3]===70&&String.fromCharCode(...b.slice(8,12))==="WEBP";if(!valid)return json({error:"Invalid image file."},400);await env.OFFERS_BUCKET.put("site/hero-image",bytes,{httpMetadata:{contentType:type}});return json({ok:true,image:"/api/hero-image"})}
  if(path==="admin/site-content"&&method==="GET"){const row=await env.DB.prepare("SELECT value FROM site_settings WHERE key=?").bind("homepage").first();let saved={};try{saved=JSON.parse(row?.value||"{}")}catch{}return json({...homeDefaults,...saved})}
  if(path==="admin/site-content"&&method==="POST"){const d=await bodyJson(request);if(!d||typeof d!=="object")return json({error:"Invalid request"},400);const limits={eyebrow:80,title:180,description:500,button:60},saved={};for(const [key,max] of Object.entries(limits)){if(typeof d[key]!=="string"||!d[key].trim()||d[key].trim().length>max)return json({error:"Invalid "+key+" text"},400);saved[key]=d[key].trim()}if(typeof d.greeting!=="string"||d.greeting.length>120||typeof d.greetingEnabled!=="boolean")return json({error:"Greeting must be up to 120 characters and have an on/off setting"},400);saved.greeting=d.greeting.trim();saved.greetingEnabled=d.greetingEnabled;for(const [key,defaultValue] of Object.entries({background:"#102b60",fontColor:"#ffffff",imageEnabled:false})){const v=d[key];if(key==="imageEnabled"){saved[key]=v===true}else if(typeof v==="string"&&/^#[0-9a-fA-F]{6}$/.test(v)){saved[key]=v}else return json({error:"Invalid "+key},400)}await env.DB.prepare("INSERT INTO site_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind("homepage",JSON.stringify(saved)).run();return json({ok:true})}

  if(path==="admin/videos"&&method==="GET"){const {results}=await env.DB.prepare("SELECT * FROM media_videos ORDER BY updated_at DESC LIMIT 200").all();return json({videos:results})}
  if(path==="admin/videos"&&method==="POST"){const d=await bodyJson(request);if(!d||typeof d!=="object")return json({error:"Invalid JSON"},400);
    let youtubeId="";try{const u=new URL(String(d.youtube_url||""));const host=u.hostname.toLowerCase();if(["youtube.com","www.youtube.com","m.youtube.com","youtube-nocookie.com","www.youtube-nocookie.com"].includes(host)){youtubeId=u.searchParams.get("v")||(u.pathname.match(/^\/(?:shorts|embed|live)\/([A-Za-z0-9_-]{11})/)||[])[1]||""}else if(host==="youtu.be"||host==="www.youtu.be"){youtubeId=u.pathname.split("/")[1]||""}}catch{}
    const title=String(d.title||"").trim(),description=String(d.description||"").trim(),category=String(d.category||"").trim(),url=String(d.url||"").trim(),cta=String(d.cta||"Learn more").trim();
    if(!/^[A-Za-z0-9_-]{11}$/.test(youtubeId))return json({error:"Invalid YouTube link. Use a regular video, Shorts, or embed URL."},400);
    if(!title||title.length>160)return json({error:"Video title must be between 1 and 160 characters."},400);
    if(description.length>600)return json({error:"Video description exceeds 600 characters ("+description.length+")."},400);
    if(!category||category.length>80||/[<>]/.test(category)||[...category].some(ch=>ch.charCodeAt(0)<32))return json({error:"Please choose a valid category (up to 80 characters)."},400);
    if(url.length>1000||(url&&!url.startsWith("https://"))||/\\s/.test(url))return json({error:"Optional product link must be an HTTPS URL, or left blank."},400);
    if(!cta||cta.length>40)return json({error:"Button text must be between 1 and 40 characters."},400);
    const id=validId(d.id)?d.id:crypto.randomUUID();await env.DB.prepare("INSERT INTO media_videos (id,youtube_id,title,description,category,url,cta,sponsored,status) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET youtube_id=excluded.youtube_id,title=excluded.title,description=excluded.description,category=excluded.category,url=excluded.url,cta=excluded.cta,sponsored=excluded.sponsored,status=excluded.status,updated_at=datetime('now')").bind(id,youtubeId,title,description,category,url,cta,d.sponsored===true?1:0,d.status==="published"?"published":"draft").run();return json({ok:true,id})}
  if(path==="admin/videos/delete"&&method==="POST"){const d=await bodyJson(request);if(!d||!validId(d.id))return json({error:"Invalid ID"},400);await env.DB.prepare("DELETE FROM media_videos WHERE id=?").bind(d.id).run();return json({ok:true})}
  // ADMIN: UPLOAD OFFER IMAGE
  if(path.startsWith('admin/ads/image/')&&method==='POST'){
    const id=path.slice('admin/ads/image/'.length);
    if(!validId(id))return json({error:'Invalid offer ID'},400);
    if(!env.OFFERS_BUCKET)return json({error:'Image storage not configured: add OFFERS_BUCKET R2 binding'},503);
    const offer=await env.DB.prepare('SELECT id FROM personal_ads WHERE id=?').bind(id).first();
    if(!offer)return json({error:'Offer not found'},404);
    let form;try{form=await request.formData()}catch{return json({error:'Invalid image upload'},400)}
    const file=form.get('image');
    if(!file||typeof file.arrayBuffer!=='function'||file.size===0||file.size>5*1024*1024||!['image/jpeg','image/png','image/webp'].includes(file.type))return json({error:'Choose a JPG, PNG or WebP image under 5 MB'},400);
    const bytes=await file.arrayBuffer();
    if(bytes.byteLength>5*1024*1024)return json({error:"Image too large"},413);
    const sig=new Uint8Array(bytes.slice(0,12));
    const jpg=sig[0]===255&&sig[1]===216&&sig[2]===255;
    const png=sig[0]===137&&sig[1]===80&&sig[2]===78&&sig[3]===71&&sig[4]===13&&sig[5]===10&&sig[6]===26&&sig[7]===10;
    const webp=String.fromCharCode(...sig.slice(0,4))==='RIFF'&&String.fromCharCode(...sig.slice(8,12))==='WEBP';
    if(!((file.type==='image/jpeg'&&jpg)||(file.type==='image/png'&&png)||(file.type==='image/webp'&&webp)))return json({error:'Invalid image file'},400);
    const b=new Uint8Array(bytes);
    if(png&&(b.length<45||String.fromCharCode(...b.slice(12,16))!=='IHDR'))return json({error:'Invalid PNG structure'},400);
    if(webp&&(b.length<30||new DataView(bytes).getUint32(4,true)+8!==b.length))return json({error:'Invalid WebP structure'},400);
    if(jpg&&(b.length<4||b[b.length-2]!==255||b[b.length-1]!==217))return json({error:'Invalid JPEG structure'},400);
    await env.OFFERS_BUCKET.put('offers/'+id,bytes,{httpMetadata:{contentType:file.type}});
    const image_url='/api/offer-image/'+id;
    await env.DB.prepare('UPDATE personal_ads SET image_url=?,updated_at=datetime(\'now\') WHERE id=?').bind(image_url,id).run();
    return json({ok:true,image_url});
  }

  // ADMIN: LIST ADS
  if (path === "admin/ads" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT * FROM personal_ads ORDER BY updated_at DESC LIMIT 100"
    ).all();

    return json({ ads: results });
  }

  // ADMIN: SAVE AD
  if (path === "admin/ads" && method === "POST") {
    const d = await bodyJson(request);

    if (!d || typeof d !== "object") {
      return json({ error: "Invalid JSON" }, 400);
    }

    const title = String(d.title || "").trim();
    const description = String(d.description || "").trim();
    const url = String(d.url || "").trim();
    const cta = String(d.cta || "Learn more").trim();
    const status =
      d.status === "published" ? "published" : "draft";

    if (
      !title ||
      title.length > 120 ||
      !description ||
      description.length > 500 ||
      !/^https:\/\/[^\s]+$/i.test(url) ||
      url.length > 1000 ||
      !cta ||
      cta.length > 40
    ) {
      return json({
        error: "Enter a valid title, description, HTTPS link and button label."
      }, 400);
    }

    const id = validId(d.id) ? d.id : crypto.randomUUID();

    await env.DB.prepare(
      "INSERT INTO personal_ads (id,title,description,url,cta,status) VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,description=excluded.description,url=excluded.url,cta=excluded.cta,status=excluded.status,updated_at=datetime('now')"
    ).bind(
      id, title, description, url, cta, status
    ).run();

    return json({ ok: true, id });
  }

  // ADMIN: DELETE AD
  if (path === "admin/ads/delete" && method === "POST") {
    const d = await bodyJson(request);

    if (!d || !validId(d.id)) {
      return json({ error: "Invalid id" }, 400);
    }

    await env.DB.prepare(
      "DELETE FROM personal_ads WHERE id=?"
    ).bind(d.id).run();

    return json({ ok: true });
  }

  // ADMIN: LIST ARTICLES
  if (path === "admin/posts" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT p.*,s.value AS cover_json FROM posts p LEFT JOIN site_settings s ON s.key=('post-cover:'||p.id) ORDER BY p.updated_at DESC LIMIT 200"
    ).all();

    return json({ posts: results.map(p=>({...p,cover:JSON.parse(p.cover_json||'{}'),cover_json:undefined})) });
  }

  if(path.startsWith("admin/article-cover/")&&method==="PUT"){const id=path.slice("admin/article-cover/".length);if(!validId(id))return json({error:"Save article first"},400);const row=await env.DB.prepare("SELECT category FROM posts WHERE id=?").bind(id).first();if(!row||!["Latest Information","Digital Guides"].includes(row.category))return json({error:"Only Latest and Guides support covers"},400);if(!env.OFFERS_BUCKET)return json({error:"R2 storage unavailable"},503);const type=(request.headers.get("content-type")||"").toLowerCase();if(!["image/jpeg","image/png","image/webp","video/mp4","video/webm"].includes(type))return json({error:"Unsupported cover format"},415);const bytes=await request.arrayBuffer();if(bytes.byteLength>(type.startsWith("video/")?15:5)*1024*1024)return json({error:"Cover too large"},413);await env.OFFERS_BUCKET.put("article-covers/"+id,bytes,{httpMetadata:{contentType:type}});const cover={type:type.startsWith("video/")?"animation":"image"};await env.DB.prepare("INSERT INTO site_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind("post-cover:"+id,JSON.stringify(cover)).run();return json({ok:true,cover})}
  if(path==="admin/article-cover-settings"&&method==="POST"){const d=await bodyJson(request);if(!validId(d?.id))return json({error:"Invalid article"},400);const row=await env.DB.prepare("SELECT category FROM posts WHERE id=?").bind(d.id).first();if(!row)return json({error:"Article not found"},404);let cover={type:"none"};if(["Latest Information","Digital Guides"].includes(row.category)&&d.type==="custom"){const heading=String(d.heading||"").trim().slice(0,120),subtitle=String(d.subtitle||"").trim().slice(0,320),color=/^#[0-9a-f]{6}$/i.test(d.color||"")?d.color:"#ffffff";const media=d.media==="animation"?"animation":"image";const existing=await env.OFFERS_BUCKET?.head("article-covers/"+d.id);if(!existing)return json({error:"Upload a picture or animation for the custom cover first"},400);const actual=existing.httpMetadata?.contentType?.startsWith("video/")?"animation":"image";if(actual!==media)return json({error:"Uploaded file does not match selected media type"},400);cover={type:"custom",media,heading,subtitle,color}}else if(["Latest Information","Digital Guides"].includes(row.category)&&d.type==="youtube"){let u;try{u=new URL(d.url)}catch{}const host=u?.hostname?.toLowerCase();let id=host==="youtu.be"?u.pathname.slice(1):["youtube.com","www.youtube.com","m.youtube.com"].includes(host)?u.searchParams.get("v"):null;if(!id&&["youtube.com","www.youtube.com"].includes(host)&&u.pathname.startsWith("/shorts/"))id=u.pathname.split("/")[2];if(!/^[a-zA-Z0-9_-]{11}$/.test(id||""))return json({error:"Enter a valid YouTube video URL"},400);cover={type:"youtube",youtubeId:id}}else if(d.type!=="none")return json({error:"Invalid cover type"},400);await env.DB.prepare("INSERT INTO site_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind("post-cover:"+d.id,JSON.stringify(cover)).run();return json({ok:true,cover})}
  // ADMIN: SAVE ARTICLE
  if (path === "admin/posts" && method === "POST") {
    const data = await bodyJson(request);

    if (!data || typeof data !== "object") {
      return json({ error: "Invalid JSON" }, 400);
    }

    const title = String(data.title || "").trim();
    const category = String(
      data.category || "Technology"
    ).trim();
    const excerpt = String(data.excerpt || "").trim();
    const body = String(data.body || "").trim();
    const source = String(data.source_url || "").trim();
    const status =
      data.status === "published" ? "published" : "draft";

    const sourceLines = source.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    const invalidSource = sourceLines.find(line => !/^https:\/\/[^\s]+$/i.test(line));
    const errors = [];
    if (!title) errors.push("Article title is missing.");
    if (title.length > 180) errors.push("Article title exceeds 180 characters.");
    if (!body || body === "BBRICH1:") errors.push("Full article text is missing.");
    if (body.length > 150000) errors.push("Full article exceeds 150,000 stored characters.");
    if (excerpt.length > 500) errors.push("Short summary exceeds 500 characters.");
    if (category.length > 80) errors.push("Category exceeds 80 characters.");
    if (source.length > 12000) errors.push("Source URLs exceed 12,000 characters.");
    if (sourceLines.length > 30) errors.push("You can add a maximum of 30 source URLs.");
    if (invalidSource) errors.push("Each source must be a complete HTTPS link, one per line. Invalid entry: " + invalidSource.slice(0, 90));
    if (errors.length) return json({ error: errors.join("\n") }, 400);

    const id = validId(data.id)
      ? data.id
      : crypto.randomUUID();

    await env.DB.prepare(
      "INSERT INTO posts (id,title,category,excerpt,body,source_url,status) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,category=excluded.category,excerpt=excluded.excerpt,body=excluded.body,source_url=excluded.source_url,status=excluded.status,updated_at=datetime('now')"
    ).bind(
      id,
      title,
      category,
      excerpt,
      body,
      source,
      status
    ).run();

    return json({ ok: true, id });
  }

  // ADMIN: DELETE ARTICLE
  if (path === "admin/delete" && method === "POST") {
    const data = await bodyJson(request);

    if (!data || !validId(data.id)) {
      return json({ error: "Invalid id" }, 400);
    }

    await env.DB.prepare(
      "DELETE FROM posts WHERE id=?"
    ).bind(data.id).run();

    return json({ ok: true });
  }

  // ADMIN: IMPORT RSS AS DRAFTS
  if (path === "admin/import" && method === "POST") {
    const feeds = [
      {
        url: "https://www.nasa.gov/feed/",
        category: "Intelligent Insights"
      },
      {
        url: "https://blog.cloudflare.com/rss/",
        category: "Technology"
      }
    ];

    let count = 0;

    for (const feed of feeds) {
      try {
        const response = await fetch(feed.url, {
          headers: {
            "user-agent": "BlayBridgeEditor/1.0"
          },
          signal: AbortSignal.timeout(7000)
        });

        if (!response.ok) continue;

        const xml = (await response.text()).slice(
          0,
          200000
        );

        const entries = [
          ...xml.matchAll(
            /<item\b[^>]*>([\s\S]*?)<\/item>|<entry\b[^>]*>([\s\S]*?)<\/entry>/gi
          )
        ].slice(0, 8);

        for (const match of entries) {
          const item = match[1] || match[2];

          const get = tag => {
            const found = item.match(
              new RegExp(
                `<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`,
                "i"
              )
            );

            return found
              ? found[1]
                  .replace(/<!\[CDATA\[|\]\]>/g, "")
                  .replace(/<[^>]+>/g, "")
                  .replace(/&amp;/g, "&")
                  .replace(/&lt;/g, "<")
                  .replace(/&gt;/g, ">")
                  .trim()
              : "";
          };

          const title = get("title").slice(0, 180);
          let link = get("link");

          if (!link) {
            link = item.match(
              /<link[^>]+href=["']([^"']+)/i
            )?.[1] || "";
          }

          if (!title || !/^https:\/\//i.test(link)) {
            continue;
          }

          const digest = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(link)
          );

          const hex = [...new Uint8Array(digest)]
            .slice(0, 16)
            .map(value =>
              value.toString(16).padStart(2, "0")
            )
            .join("");

          const id =
            `${hex.slice(0, 8)}-` +
            `${hex.slice(8, 12)}-` +
            `4${hex.slice(13, 16)}-` +
            `a${hex.slice(17, 20)}-` +
            `${hex.slice(20, 32)}`;

          const excerpt = (
            get("description") || get("summary")
          ).slice(0, 450);

          const body =
            "SOURCE-BASED DRAFT — verify facts, write your own original explanation, and cite the source before publishing.\n\n" +
            `Original headline: ${title}\n\n` +
            `Source: ${link}`;

          const result = await env.DB.prepare(
            "INSERT OR IGNORE INTO posts (id,title,category,excerpt,body,source_url,status) VALUES (?,?,?,?,?,?,'draft')"
          ).bind(
            id,
            title,
            feed.category,
            excerpt,
            body,
            link
          ).run();

          count += result.meta.changes || 0;
        }
      } catch {
        // Continue if a feed is unavailable.
      }
    }

    return json({
      ok: true,
      created: count,
      message:
        "Source-linked drafts imported for review. No articles published."
    });
  }

  return json({ error: "Not found" }, 404);
}
