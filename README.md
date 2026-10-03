# Aurelis ACI

Aurelis ACI is an operational control, assurance, evidence and intelligence layer for AI systems.

## Product architecture

Aurelis is problem-led rather than limited to a fixed set of domains. The initial capability catalog contains:

1. AI Identity
2. AI Spend Infrastructure
3. AI Incident Infrastructure
4. AI Recovery Infrastructure
5. AI Supply-Chain Infrastructure
6. AI Vendor Risk Infrastructure
7. AI Compliance Evidence Infrastructure
8. AI Data-Access Control
9. AI-to-AI Trust Infrastructure
10. AI Assurance Infrastructure
11. AI Observability & Business Outcomes Infrastructure

The core engine is reusable across future capabilities.

## Security model

- Client plane and admin plane are separate.
- Human admin access uses Google identity + exact allowlist + secure server-side session.
- MFA/passkey can be enforced through the identity provider; Aurelis never stores a Google password.
- No hardcoded admin key is used by the browser.
- Tenant is derived from the authenticated session, never from a client-supplied tenant_id.
- Capability entitlements are checked server-side on every protected operation.
- Programmatic API credentials are separate from human admin authentication and are scoped, revocable and auditable.

## Local development

1. Copy `.dev.vars.example` to `.dev.vars` and configure Google OAuth if testing authentication.
2. Replace the D1 database ID in `wrangler.toml` before deployment.
3. Install dependencies with `npm install`.
4. Run `npm test`.
5. Run `npm run validate`.
6. Run `npm run dev`.

The public demo works without external credentials and uses deterministic sandbox data. It is clearly labeled as a sandbox.

## Production deployment

Create a Cloudflare D1 database, put its ID into `wrangler.toml`, apply `db/schema.sql`, configure secrets/vars, then deploy the Pages project. Google OAuth redirect URI must match the deployed `/api/auth/google/callback` URL exactly.

Do not publish `.dev.vars` or OAuth secrets.
