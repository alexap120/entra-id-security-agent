# 🛡️ EntraGoat Scenario 2: Graph Me the Crown (and Roles)

## 1. Executive Summary & Details

- **Target Scenario:** EntraGoat Scenario 2
- **Attacker Identity:** `jennifer.clark@wwlx355921.onmicrosoft.com` (initial recon) → `Corporate Finance Analytics` (service principal)
- **Target Identity:** `EntraGoat-admin-s2@wwlx355921.onmicrosoft.com`
- **Captured Flag:** `EntraGoat{4P1_P37mission_4bus3_Succ3ss!}`

## 2. Technical Walkthrough & Exploitation

1. **Initial Reconnaissance:** Authenticated as `jennifer.clark` via `Connect-MgGraph`. Confirmed no active directory role assignments and no meaningful group memberships. The low-privileged user context is used only for initial recon — the real foothold comes from the leaked certificate.

2. **Credential Discovery:** Decoded the leaked Base64-encoded `.pfx` certificate string found in CI/CD pipeline build output. Loaded it as an `X509Certificate2` object and inspected its subject (`CN=Corporate Finance Analytics`), thumbprint, and validity window.

3. **Identity Resolution — Two Approaches:**
   - **Direct lookup:** Queried `Get-MgServicePrincipal -Filter "displayName eq 'Corporate Finance Analytics'"` to retrieve the SP's `AppId` and object ID.
   - **Thumbprint-based lookup:** Iterated all app registrations via `Get-MgApplication -All` and matched the certificate thumbprint against each app's `KeyCredentials.CustomKeyIdentifier` — useful when the SP name is not known in advance.

4. **Service Principal Authentication:** Disconnected the user session and authenticated directly as the SP using the certificate via `Connect-MgGraph -ClientId $appId -Certificate $cert` (OAuth2 client credentials flow). Note: even if certificate-based authentication is disabled for users in the tenant, SPs always support certificate auth via the client credentials flow — user CBA policy does not apply to SP authentication.

5. **Permission Discovery:** Confirmed via `Get-MgContext` that the SP held **`AppRoleAssignment.ReadWrite.All`** as an application permission. This permission allows the SP to grant *any* Graph API app role to *any* service principal in the tenant — including itself. It is effectively a meta-permission: holding it collapses the entire Graph permission model, as it can be used to self-grant any other permission on demand.

6. **Permission Self-Escalation:** Located the Microsoft Graph service principal (appId `00000003-0000-0000-c000-000000000000`) and retrieved the app role definition for **`RoleManagement.ReadWrite.Directory`**. Granted this role to the `Corporate Finance Analytics` SP via `New-MgServicePrincipalAppRoleAssignment`. This permission grants the ability to assign any directory role — including Global Administrator — to any security principal.

7. **Token Refresh:** Disconnected and re-authenticated as the SP to obtain a new token. App-only permissions are static claims in the JWT — the newly granted `RoleManagement.ReadWrite.Directory` permission is not usable until a fresh token is issued. May require a short wait for permission propagation before the new token reflects the grant.

8. **Global Administrator Self-Assignment:** Using `RoleManagement.ReadWrite.Directory`, retrieved the GA directory role object (template ID `62e90394-69f5-4237-9190-012177145e10`) and added the SP as a member via `New-MgDirectoryRoleMemberByRef`. The SP was now a de-facto Global Administrator.

9. **Account Compromise:** Located the target administrator (`EntraGoat-admin-s2`) and reset their password via `Update-MgUser -PasswordProfile`.

10. **Flag Retrieval:** Disconnected the SP session and authenticated as `EntraGoat-admin-s2` using the reset password (ROPC flow). Issued a Graph call to `/v1.0/me?$select=onPremisesExtensionAttributes` and extracted the flag from `extensionAttribute1`.

## 3. Root Cause Analysis

- **`AppRoleAssignment.ReadWrite.All` is a Meta-Permission:** This single permission grants the ability to assign any Graph API app role to any principal in the tenant, including the SP that holds it. In practice it is equivalent to holding all Graph application permissions simultaneously — any permission the attacker needs can be self-granted on demand. Granting this permission to any SP should be treated as granting full tenant compromise capability.

- **Certificate Leakage is as Dangerous as Password Leakage:** A certificate private key exposed in CI/CD logs or pipeline artifacts gives an attacker everything needed to authenticate as the SP — no password, no MFA, no user interaction required. Unlike passwords, leaked certificates often go undetected because rotation and monitoring tooling is less mature for certificate credentials than for secrets.

- **SP Certificate Authentication Cannot Be Disabled Tenant-Wide:** User certificate-based authentication (CBA) can be enabled or disabled per tenant policy. SP authentication via client certificates follows the OAuth2 client credentials flow and is always available regardless of user CBA settings — a distinction that is frequently misunderstood.

- **App Permission Grants Are Permanent Until Explicitly Revoked:** Once `New-MgServicePrincipalAppRoleAssignment` succeeds, the permission persists in the directory. There is no time-limit or session scope — the SP retains `RoleManagement.ReadWrite.Directory` until an administrator explicitly removes the assignment.

- **JWT Claims Are Static — Token Refresh Required After Permission Grant:** App-only permissions are embedded as static claims in the access token at issuance time. A newly granted permission is not reflected in the current token — requiring a disconnect and re-authentication. This is an important operational detail for both attackers (must refresh to use new permissions) and defenders (a disconnect/reconnect immediately after an unusual permission grant is a detectable signal).

## 4. Mitigation & Remediation

- Treat `AppRoleAssignment.ReadWrite.All` as a Tier-0 permission equivalent to Global Administrator — no SP should hold this permission unless it is a strictly governed, dedicated provisioning service with no exposure to CI/CD pipelines or developer workflows.
- Immediately revoke the compromised certificate under App Registrations → `Corporate Finance Analytics` → Certificates & secrets, and rotate all credentials for the SP.
- Implement secret and certificate scanning in CI/CD pipelines (e.g., Gitleaks, truffleHog, GitHub secret scanning) to detect private key material in build logs, artifacts, and repository history before it is exposed.
- Audit all service principals holding `AppRoleAssignment.ReadWrite.All` or `RoleManagement.ReadWrite.Directory` and remove these permissions unless strictly required — treat any SP holding either as a critical risk.
- Monitor `New-MgServicePrincipalAppRoleAssignment` events — particularly any grant where the SP is assigning a permission to itself. This is the core privilege escalation action and should be a high-severity alert.
- Monitor SP authentication events using certificate credentials, especially where the authenticating SP holds or shortly thereafter gains high-impact permissions.
- Alert on the correlated sequence: SP certificate authentication → self-grant of `RoleManagement.ReadWrite.Directory` → SP token refresh → directory role assignment → privileged user password reset. Each event is auditable; together they are the complete attack chain.
- Enforce a certificate lifecycle management process: certificate expiry alerts, rotation schedules, and inventory of which SPs hold certificate credentials — certificate sprawl is the initial condition that makes this scenario possible.
