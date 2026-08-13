# 🛡️ EntraGoat Scenario 6: CBA Root Access

## 1. Executive Summary & Details

- **Target Scenario:** EntraGoat Scenario 6
- **Attacker Identity:** `Legacy-Automation-Service` → pivot to `terence.mckenna` (compromised user) → pivot to `DataSync-Production` (service principal)
- **Target Identity:** `EntraGoat-admin-s6@wwlx355921.onmicrosoft.com`
- **Captured Flag:** `EntraGoat{C3rt_Byp@ss_R00t3d_4dm1n}`

## 2. Technical Walkthrough & Exploitation

1. **Credential Discovery:** Identified a hardcoded client secret in the legacy `legacy_sync_task.ps1` script for `Legacy-Automation-Service`.
2. **Application Authentication:** Authenticated via OAuth2 client-credentials flow. `Get-MgContext` confirmed scopes `Directory.Read.All` and `Application.ReadWrite.OwnedBy`.
3. **Application Ownership Discovery:** Enumerated all service principals in the tenant and checked ownership against the current principal, finding `DataSync-Production` owned by `Legacy-Automation-Service`.
4. **Privilege Discovery on `DataSync-Production`:** No directory role assignments. Its Graph app-role assignments showed `Directory.Read.All` and `Organization.ReadWrite.All` — the latter is sufficient to add a root CA to the tenant, but not to enable CBA itself.
5. **Backdooring the Owned SP:** Used `Application.ReadWrite.OwnedBy` to add a new client secret to `DataSync-Production` via `Add-MgServicePrincipalPassword`.
6. **Dead End Confirmed:** Attempted to read the CBA policy config (`Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration`) both as `Legacy-Automation-Service` and as `DataSync-Production` — both returned 403. Neither identity can enable CBA.
7. **Pivot to User Context:** Authenticated as the compromised user `terence.mckenna` (ROPC flow). Checked directory role assignments (none), group memberships (none beyond default), and owned directory objects via `Get-MgUserOwnedObject` (none).
8. **PIM Eligibility Discovery:** Queried `identityGovernance/privilegedAccess/group/eligibilitySchedules` and found Terence eligible for member access to the `Authentication Policy Managers` group, which carries the `Authentication Policy Administrator` and `Application Administrator` directory roles.
9. **PIM Self-Activation:** Self-activated the eligible assignment via `POST .../group/assignmentScheduleRequests` (8-hour duration), gaining active membership and the associated roles.
10. **Enabling CBA:** Reconnected with the `Policy.ReadWrite.AuthenticationMethod` delegated scope under Terence's now-privileged context and enabled tenant-wide CBA (initially `x509CertificateSingleFactor`) via `Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration`.
11. **Malicious Root CA Upload:** Reconnected as `DataSync-Production` using the client secret from step 5, invoking `Organization.ReadWrite.All` to POST/PATCH a self-generated rogue root CA into `organization/{tenantId}/certificateBasedAuthConfiguration`, and verified the upload by thumbprint match.
12. **Certificate Forgery:** Used OpenSSL (not PowerShell/.NET, which can't produce the required OID) to generate a client certificate for `EntraGoat-admin-s6`, embedding the UPN in the SAN via the `1.3.6.1.4.1.311.20.2.3` otherName OID, and signed it with the rogue root CA. Packaged as `.pfx`.
13. **MFA Binding Bypass:** Initial CBA login reached the "Choose a way to sign in" MFA prompt because the default mode was single-factor. Using the still-active `Authentication Policy Administrator` context, updated `x509CertificateAuthenticationDefaultMode` to `x509CertificateMultiFactor`.
14. **Impersonation & Flag Retrieval:** Imported the forged `.pfx` locally, authenticated passwordlessly as `EntraGoat-admin-s6` via CBA at the Entra/Azure portal, and retrieved the flag as a fully authenticated Global Administrator.

## 3. Root Cause Analysis

- **Hardcoded Credentials:** Client secret stored in plaintext in a legacy automation script.
- **Excessive Application Permissions:** `Legacy-Automation-Service` held `Application.ReadWrite.OwnedBy`, letting it manage credentials on any SP it owns.
- **Unaudited Service Principal Ownership:** `DataSync-Production` was owned by another SP — invisible to normal auditing flows and impossible to configure via the Azure Portal UI in the first place (only via Graph directly), which makes it easy to miss.
- **Overlooked High-Impact Permission:** `Organization.ReadWrite.All` allowed modifying tenant-wide authentication configuration, including the trusted CA list — despite not granting any user/group/role management rights on its own.
- **PIM-Eligible Group Misassignment:** A low-privileged user was eligible (via group-based PIM) for `Authentication Policy Managers`, granting `Authentication Policy Administrator` (used) and `Application Administrator` (available but unused alternate path) via simple self-activation with a free-text justification.
- **CBA Trust Boundary Abuse:** Once enabled, any uploaded root CA becomes a valid identity issuer for every user in the tenant — combined with `Organization.ReadWrite.All`, this let a compromised low-tier SP establish a persistent, passwordless admin-impersonation path.
- **Weak Default Authentication Binding:** CBA's default authentication strength was single-factor, and nothing prevented the same compromised role from reclassifying it as MFA-satisfying, letting a forged certificate alone satisfy MFA on a Global Admin sign-in.

## 4. Mitigation & Remediation

- Remove hardcoded secrets from source code; use a secrets manager and rotate any exposed credentials immediately.
- Apply least privilege to service principals — treat `Application.ReadWrite.OwnedBy` and `Organization.ReadWrite.All` as high-risk grants, not routine automation scopes.
- Audit service-principal-to-service-principal ownership specifically — it's a Graph-only relationship the Portal UI can display but not create, making it easy to overlook.
- Audit and restrict PIM-eligible assignments (direct and group-based) for privileged roles like `Authentication Policy Administrator` and `Application Administrator`; require approval workflows rather than free-text self-activation.
- Treat `Organization.ReadWrite.All` as Tier-0 — it governs tenant-wide authentication policy, not just branding/org profile.
- Monitor `certificateBasedAuthConfiguration` changes and new root CA additions as high-severity alerts.
- Enforce `x509CertificateMultiFactor` as the mandatory default binding mode for CBA, especially for any account eligible for privileged roles.
- Correlate service-principal authentication, secret/certificate additions, ownership changes, PIM activations, and authentication-policy modifications — each is low-signal alone but high-signal in sequence.
