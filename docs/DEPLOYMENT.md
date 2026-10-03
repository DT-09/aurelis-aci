# Deployment

1. Create Cloudflare Pages project.
2. Create D1 database.
3. Put the D1 ID in `wrangler.toml`.
4. Apply `db/schema.sql` with Wrangler D1 tooling.
5. Configure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `ADMIN_EMAILS`, `GOOGLE_REDIRECT_URI` and `SESSION_SECRET` as secrets/vars.
6. Configure the exact Google OAuth callback URL.
7. Run `npm test`, `npm run validate` and `npm run smoke`.
8. Deploy Pages.

Never commit OAuth or session secrets.
