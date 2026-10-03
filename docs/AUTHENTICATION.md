# Authentication

Customer authentication is invitation-based. Admin authentication uses Google OAuth plus an exact email allowlist. The system never stores a Google password and never uses a hardcoded browser admin key. Sessions are stored server-side and represented to the browser with an HttpOnly, Secure, SameSite cookie.
