import { EDITORIAL_POSTS } from "../../editorial-data.js";
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff"}});
export async function onRequestGet({env}){
 const byId=new Map(EDITORIAL_POSTS.map(post=>[post.id,post]));
 if(env.DB){
  const {results}=await env.DB.prepare("SELECT p.id,p.title,p.category,p.excerpt,p.body,p.source_url,p.updated_at,s.value AS cover_json FROM posts p LEFT JOIN site_settings s ON s.key=('post-cover:'||p.id) WHERE p.status='published' AND p.updated_at >= ? ORDER BY p.updated_at DESC LIMIT 100").bind("2026-10-28 00:00:00").all();
  const staticCovers=new Map(EDITORIAL_POSTS.filter(post=>post.cover?.type==='image'&&post.cover.url).map(post=>[post.id,post.cover]));
  for(const post of results){
   let cover={};
   try{cover=JSON.parse(post.cover_json||'{}')}catch{}
   if((!cover.type||cover.type==='none')&&staticCovers.has(post.id))cover=staticCovers.get(post.id);
   byId.set(post.id,{...post,created_at:post.updated_at,date:post.updated_at,cover,cover_json:undefined});
  }
 }
 return json({posts:[...byId.values()]});
}
