# Security

Aurelis ACI is designed around least privilege, tenant isolation and auditable control decisions.

## Admin access

Admin access is server-authorized. The browser never contains a permanent admin secret. Google OAuth authenticates the human identity; `ADMIN_EMAILS` determines which identities may enter the admin plane. Sensitive actions should require reauthentication or an identity-provider MFA/passkey policy.

## Tenant isolation

Client API handlers derive tenant identity from the session. A request cannot select another tenant by modifying a browser parameter. Database queries must include the authenticated tenant scope.

## Entitlements

Capability access is an authorization decision, not a UI decision. The server checks the tenant's active entitlement before executing protected capability actions.

## Evidence

Operational decisions create immutable-style evidence records containing event, context, policy, decision and action references. Production retention and deletion policy should be configured per deployment requirements.

## Limitations

This repository does not claim SOC 2, ISO 27001, HIPAA, FedRAMP or other certification. Customers must perform their own security and compliance assessment.
