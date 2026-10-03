# Architecture

Aurelis ACI has three layers: Client Plane, Admin Plane, and Core Engine. The Core Engine contains reusable discovery, control, policy, intelligence, assurance, evidence and remediation primitives. Capabilities are compositions of these primitives rather than isolated dashboards.

## Runtime boundary

Cloudflare Pages serves the UI and Pages Functions provide the API. D1 stores tenant-scoped operational state. OAuth is handled server-side. The browser receives only an HttpOnly session cookie and short-lived application data.
