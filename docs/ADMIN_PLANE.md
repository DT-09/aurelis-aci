# Admin Plane

The Admin Plane is a separate operational surface for Aurelis operators. Human authentication is Google OAuth plus exact `ADMIN_EMAILS` allowlisting and server-side session authorization. The admin plane provisions tenants, grants entitlements, creates invitation links, reviews control requests, inspects audit records and checks system health.

The browser never receives a permanent admin credential. A programmatic credential, when required, is separate from human admin authentication and should be scoped and rotated.
