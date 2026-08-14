# 🛡️ EntraGoat Scenario 1: Misowned and Dangerous

## 1. Executive Summary & Details

- **Target Scenario:** EntraGoat Scenario 1
- **Attacker Identity:** `david.martinez@wwlx355921.onmicrosoft.com`
- **Target Identity:** `EntraGoat-admin-s1@wwlx355921.onmicrosoft.com`
- **Captured Flag:** (retrieved from `extensionAttribute1` after full tenant compromise)

## 2. Technical Walkthrough & Exploitation

1. **Initial Reconnaissance:** Authenticated as `david.martinez` via `Connect-MgGraph`. Confirmed no active directory role assignments and no group memberships beyond the default tenant group. No owned groups found.

2. **Owned SP Discovery:** Enumerated service principals the current user owns. Two approaches exist:
   - **Slow path:** Iterate all SPs in the tenant via `Get-MgServicePrincipal -All` and check each SP's owner list individually — generates hundreds of API requests and a large log footprint.
   - **Efficient path:** `Get-MgUserOwnedObject` returns all directory objects owned by the user (groups, apps, SPs) in a single call — far fewer requests and minimal detection surface.
   
   Both paths surface the same result: `david.martinez` is an explicit owner of the **`Finance Analytics Dashboard`** service principal.

3. **SP Privilege Discovery:** Checked the SP's Graph app-role assignments — none found. Checked its directory role assignments via `Get-MgRoleManagementDirectoryRoleAssignment` and found: **`Privileged Authentication Administrator`** (PAA), assigned tenant-wide. PAA grants the ability to reset passwords and modify authentication methods for any user in the tenant, including Global Administrators.

4. **Credential Injection:** As an owner of the SP, added a new client secret via `Add-MgServicePrincipalPassword` — no approval, no alert, entirely valid platform behavior. Saved the generated secret for the pivot step.

5. **Pivot to Service Principal Context:** Disconnected the David session and re-authenticated using the SP's `AppId` and the newly added client secret via `Connect-MgGraph -ClientSecretCredential` (app-only flow). Confirmed the SP context and its PAA role via `Get-MgContext`.

6. **Account Compromise:** Located the target administrator (`EntraGoat-admin-s1`) and reset their password via `Update-MgUser -PasswordProfile`. As an alternative, issued a **Temporary Access Pass** (TAP) via `New-MgUserAuthenticationTemporaryAccessPassMethod` — a time-limited passcode usable to authenticate without MFA, bypassing any MFA enforcement on the admin account without triggering a password reset event.

7. **Flag Retrieval:** Disconnected the SP session and authenticated as `EntraGoat-admin-s1` using the reset password (ROPC flow). Issued a Graph call to `/v1.0/me?$select=onPremisesExtensionAttributes` and extracted the flag from `extensionAttribute1`.

## 3. Root Cause Analysis

- **SP Ownership Grants Credential Management by Design:** Microsoft allows SP owners to add and remove credentials (secrets and certificates) without additional approval or elevated permissions. This is intentional platform behavior — but when the SP holds a sensitive directory role, ownership becomes a direct privilege escalation path. There is no native control that prevents a low-privileged owner from injecting credentials into a high-privileged SP.

- **Low-Privileged User as SP Owner:** `david.martinez` held no directory roles and no group-based privileges. The only misconfiguration was ownership of one SP. This can happen when: app registrations are open by default and a user creates an app that later receives elevated roles; ownership is granted temporarily and never revoked; or a multi-tenant app is consented to and the user is assigned as owner.

- **PAA Scope Includes Global Administrators:** Privileged Authentication Administrator is commonly assumed to be limited to non-admin users. In fact, PAA can reset passwords and authentication methods for Global Administrators — making any SP or user holding this role a full tenant-compromise path.

- **Delegated vs. App-Only Authentication Boundary:** David's delegated token as a standard user carried no meaningful permissions. By pivoting to the SP's app-only token, the attacker crossed into a completely different permission boundary — the SP's directory roles — without any additional approval or MFA requirement on the SP authentication itself.

- **Ownership Chains Are Rarely Audited:** Standard access reviews focus on direct role assignments to users. SP ownership by non-admin users, and the roles those SPs hold, are rarely included in the same review scope — leaving this path invisible to routine governance processes.

## 4. Mitigation & Remediation

- Audit all service principal owners and remove non-administrative user accounts from the owner list of any SP that holds a directory role or sensitive Graph permissions; SP ownership should be restricted to break-glass accounts or governed service accounts.
- Restrict app registration to administrators only (Entra ID → User settings → "Users can register applications" → No) to prevent low-privileged users from creating SPs that may later accumulate roles.
- Treat `Privileged Authentication Administrator` as Tier-0 — it grants password reset capability over Global Administrators. Any SP or user holding this role should be subject to the same governance controls as GA itself.
- Alert on client secret or certificate additions to service principals that hold privileged directory roles; this event is the critical pivot point in the attack chain and should be a high-severity signal.
- Alert on app-only authentication events from service principals that hold PAA, PRA, or GA roles, especially where a new credential was recently added.
- Include SP ownership in Entra ID Access Reviews — review not just who is a member or owner of groups, but who owns service principals that hold elevated roles or permissions.
- Consider requiring Workload Identity credentials to be managed through a governed pipeline (e.g. federated credentials tied to a managed identity or CI/CD system) rather than allowing manual secret addition via Graph API.
- Correlate the sequence: new credential added to SP → app-only authentication using that credential → privileged user attribute modification. Each event is individually auditable; together they are the complete attack chain.
