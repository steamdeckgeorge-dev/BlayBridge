
const json = (value, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
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

  // PUBLIC ARTICLES
  if (path === "posts" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id,title,category,excerpt,body,source_url,updated_at FROM posts WHERE status='published' ORDER BY updated_at DESC LIMIT 100"
    ).all();

    return json({ posts: results });
  }

  // PUBLIC ADVERTISEMENTS
  if (path === "ads" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id,title,description,url,cta FROM personal_ads WHERE status='published' ORDER BY updated_at DESC LIMIT 12"
    ).all();

    return json({ ads: results });
  }

  // ADMIN AUTHENTICATION
  const failure = await checkAccess(request, env);

  if (failure) {
    return json({
      error: "Unauthorised. Configure Cloudflare Access and log in.",
      ...failure
    }, 401);
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
      "SELECT * FROM posts ORDER BY updated_at DESC LIMIT 200"
    ).all();

    return json({ posts: results });
  }

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

    if (
      !title ||
      title.length > 180 ||
      !body ||
      body.length > 30000 ||
      excerpt.length > 500 ||
      category.length > 80 ||
      source.length > 1000 ||
      (source && !/^https:\/\//i.test(source))
    ) {
      return json({
        error: "Check title, body, excerpt, category and HTTPS source URL."
      }, 400);
    }

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
