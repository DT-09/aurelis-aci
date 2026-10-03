# Entitlements

Capabilities are server-side entitlements. UI visibility is advisory; API authorization is authoritative. Every protected capability request resolves the tenant from the session and checks an ACTIVE entitlement. Unentitled direct API calls return `403 CAPABILITY_NOT_ENTITLED`.
