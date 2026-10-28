import { EDITORIAL_POSTS } from "../../editorial-data.js";
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff"}});
export async function onRequestGet({env}){
 const byId=new Map(EDITORIAL_POSTS.map(post=>[post.id,post]));
 if(env.DB){
  const {results}=await env.DB.prepare("SELECT id,title,category,excerpt,body,source_url,updated_at FROM posts WHERE status='published' AND updated_at >= ? ORDER BY updated_at DESC LIMIT 100").bind("2026-10-28 00:00:00").all();
  for(const post of results)byId.set(post.id,{...post,created_at:post.updated_at,date:post.updated_at,cover:{type:"none"}});
 }
 return json({posts:[...byId.values()]});
}
