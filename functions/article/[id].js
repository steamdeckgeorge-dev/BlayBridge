// Server-rendered social cards for BlayBridge articles.
// Fragment URLs (#article=...) are invisible to social crawlers, so share /article/ID instead.
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export async function onRequestGet({params,env,request}) {
  const id=String(params.id||'');
  if(!/^[0-9a-f-]{36}$/i.test(id)) return new Response('Article not found',{status:404});
  if(!env.DB) return new Response('Service temporarily unavailable',{status:503});
  const post=await env.DB.prepare("SELECT id,title,excerpt,status FROM posts WHERE id=? AND status='published'").bind(id).first();
  if(!post) return new Response('Article not found',{status:404});
  const origin=new URL(request.url).origin;
  const canonical=origin+'/article/'+encodeURIComponent(id);
  const image=origin+'/api/article-cover/'+encodeURIComponent(id);
  const home=origin+'/#article='+encodeURIComponent(id);
  const title=escapeHtml(post.title),description=escapeHtml(post.excerpt||post.title),url=escapeHtml(canonical),cover=escapeHtml(image);
  // Social preview crawlers should receive a stable, server-rendered document without a client-side navigation.
  const isCrawler=/Twitterbot|facebookexternalhit|Facebot|LinkedInBot|Slackbot|Discordbot|WhatsApp|TelegramBot|Googlebot|bingbot/i.test(request.headers.get('user-agent')||'');
  const redirectScript=isCrawler?'':`<script>location.replace(${JSON.stringify(home)})</script>`;
  const html=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} | BlayBridge</title><meta name="description" content="${description}"><link rel="canonical" href="${url}"><meta property="og:type" content="article"><meta property="og:site_name" content="BlayBridge"><meta property="og:title" content="${title}"><meta property="og:description" content="${description}"><meta property="og:url" content="${url}"><meta property="og:image" content="${cover}"><meta property="og:image:secure_url" content="${cover}"><meta property="og:image:alt" content="${title}"><meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="${title}"><meta name="twitter:description" content="${description}"><meta name="twitter:image" content="${cover}"><meta name="twitter:image:alt" content="${title}">${redirectScript}</head><body><main><h1>${title}</h1><p>${description}</p><p><a href="${escapeHtml(home)}">Read this article on BlayBridge</a></p></main></body></html>`;
  return new Response(html,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'public, max-age=120'}});
}