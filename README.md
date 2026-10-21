# BlayBridge — Cloudflare Pages + D1

## Deploy
1. Create a free Cloudflare account and a Pages project. **Use Git integration** (recommended) with this folder committed to a GitHub repository. Pages Functions under `functions/` require a deployment method that supports Functions; do not use the static-only drag-and-drop method for this version.
2. Create a Cloudflare D1 database, then bind it to the Pages project as `DB` in Settings → Bindings.
3. Run `schema.sql` against the D1 database (D1 Console or Wrangler) before using the editor.
4. In Cloudflare Zero Trust → Access → Applications, create a self-hosted application protecting BOTH `your-domain/admin/*` and `your-domain/api/admin/*` (use two applications if necessary). Allow only your verified email address and enable strong identity-provider MFA. Protecting `/admin/` alone is NOT sufficient.
5. Set Pages environment variables `ACCESS_TEAM_DOMAIN` (e.g. `your-team.cloudflareaccess.com`) and `ACCESS_AUD` (the Access application AUD tag for the API-protecting application). Redeploy.
6. Visit `https://your-domain/admin/` to create articles and personal ads. Use Import new drafts to collect source-linked topics for manual rewriting and approval. This is semi-automatic, not AI-written or scheduled publication.
7. Published personal promotions show in the labelled **From BlayBridge · Sponsored** section. Google AdSense placeholders are separate and require approval and your own AdSense integration.

## Important security and launch notes
- API admin routes validate signed Cloudflare Access JWTs. Do not remove this validation or expose admin routes without Access.
- The starter's sample articles are static; new D1 articles need a public front-end integration before they appear in the homepage. The public `/api/posts` endpoint is ready.
- Replace the placeholder contact email, review privacy/terms for your actual data practices, and test all production routes before launch.
- No credentials, API keys, or paid AI services are bundled.
