import { EDITORIAL_POSTS } from "../../editorial-data.js";
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export async function onRequestGet({params,env,request}) {
  const id=String(params.id||'');
  const curated=EDITORIAL_POSTS.find(item=>item.id===id);
  let post=curated;
  if(!post&&env.DB&&/^[0-9a-f-]{36}$/i.test(id))post=await env.DB.prepare("SELECT id,title,excerpt,status,updated_at FROM posts WHERE id=? AND status='published' AND updated_at >= ?").bind(id,"2026-10-28 00:00:00").first();
  if(!post)return new Response('Article not found',{status:404});
  const origin=new URL(request.url).origin,canonical=origin+'/article/'+encodeURIComponent(id),home=origin+'/#article='+encodeURIComponent(id);
  const title=escapeHtml(post.title),description=escapeHtml(post.excerpt||post.title),url=escapeHtml(canonical);
  const isCrawler=/Twitterbot|facebookexternalhit|Facebot|LinkedInBot|Slackbot|Discordbot|WhatsApp|TelegramBot|Googlebot|bingbot/i.test(request.headers.get('user-agent')||'');
  const redirectScript=isCrawler?'':`<script>location.replace(${JSON.stringify(home)})</script>`;
  const html=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} | BlayBridge</title><meta name="description" content="${description}"><link rel="canonical" href="${url}"><meta property="og:type" content="article"><meta property="og:site_name" content="BlayBridge"><meta property="og:title" content="${title}"><meta property="og:description" content="${description}"><meta property="og:url" content="${url}"><meta name="twitter:card" content="summary"><meta name="twitter:title" content="${title}"><meta name="twitter:description" content="${description}">${redirectScript}</head><body><main><h1>${title}</h1><p>${description}</p><p><a href="${escapeHtml(home)}">Read this article on BlayBridge</a></p></main></body></html>`;
  return new Response(html,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'public, max-age=120'}});
}
