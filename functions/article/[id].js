import { EDITORIAL_POSTS } from "../../editorial-data.js";

const esc=value=>String(value??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));

export async function onRequest(context){
  const {request,params,env}=context;
  const response=await context.next();
  const type=response.headers.get("content-type")||"";
  const id=String(params.id||"");
  if(request.method!=="GET"||!type.includes("text/html")||!/^[a-f0-9-]{36}$/i.test(id))return response;

  let article=EDITORIAL_POSTS.find(post=>post.id===id);
  let cover=article?.cover||null;

  // Public stories are stored in D1, so resolve them server-side for social crawlers.
  if(env.DB){
    const row=await env.DB.prepare(
      "SELECT p.id,p.title,p.excerpt,s.value AS cover_json FROM posts p LEFT JOIN site_settings s ON s.key=('post-cover:'||p.id) WHERE p.id=? AND p.status='published' LIMIT 1"
    ).bind(id).first();
    if(row){
      article={...article,...row};
      try{cover=JSON.parse(row.cover_json||"{}");if(!cover.url&&article?.cover?.url)cover=article.cover}catch{cover=article?.cover||{}}
    }else if(!article){
      return response;
    }
  }

  if(!article)return response;
  const url=new URL("/article/"+encodeURIComponent(id),request.url).href;
  let image="";
  if(cover?.url&&["image","animation","custom"].includes(cover.type)){
    image=new URL(cover.url,request.url).href;
  }else if(cover&&["image","animation","custom"].includes(cover.type)){
    image=new URL("/api/article-cover/"+encodeURIComponent(id),request.url).href;
  }
  const title=article.title+" | BlayBridge";
  const description=article.excerpt||"Read this story on BlayBridge.";
  const tags=[
    '<link rel="canonical" href="'+esc(url)+'">',
    '<meta property="og:type" content="article">',
    '<meta property="og:site_name" content="BlayBridge">',
    '<meta property="og:title" content="'+esc(title)+'">',
    '<meta property="og:description" content="'+esc(description)+'">',
    '<meta property="og:url" content="'+esc(url)+'">',
    image?'<meta property="og:image" content="'+esc(image)+'">':'',
    image?'<meta property="og:image:secure_url" content="'+esc(image)+'">':'',
    image?'<meta property="og:image:width" content="1200">':'',
    image?'<meta property="og:image:height" content="630">':'',
    image?'<meta property="og:image:alt" content="'+esc(cover?.alt||article.title)+'">':'',
    '<meta name="twitter:card" content="summary_large_image">',
    '<meta name="twitter:title" content="'+esc(title)+'">',
    '<meta name="twitter:description" content="'+esc(description)+'">',
    image?'<meta name="twitter:image" content="'+esc(image)+'">':'',
    image?'<meta name="twitter:image:alt" content="'+esc(cover?.alt||article.title)+'">':''
  ].filter(Boolean).join("");
  let html=await response.text();
  html=html.replace(/<title>[\s\S]*?<\/title>/i,"<title>"+esc(title)+"</title>");
  html=html.replace(/<meta\s+name=["']description["'][^>]*>/i,'<meta name="description" content="'+esc(description)+'">');
  html=html.replace(/<\/head>/i,tags+"</head>");
  const headers=new Headers(response.headers);
  headers.set("content-type","text/html; charset=utf-8");
  headers.set("cache-control","public, max-age=300");
  return new Response(html,{status:response.status,statusText:response.statusText,headers});
}
