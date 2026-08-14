# 🛡️ EntraGoat Scenario 3: Group MemberShipwreck

## 1. Executive Summary & Details

- **Target Scenario:** EntraGoat Scenario 3
- **Attacker Identity:** `michael.chen@wwlx355921.onmicrosoft.com`
- **Target Identity:** `EntraGoat-admin-s3@wwlx355921.onmicrosoft.com`
- **Captured Flag:** `EntraGoat{Gr0up_Ch@1n_Pr1v_Esc@l@t10n!}`

## 2. Technical Walkthrough & Exploitation

1. **Initial Reconnaissance:** Authenticated as `michael.chen` via `Connect-MgGraph`. Confirmed no active directory role assignments and no current group memberships beyond defaults.

2. **Owned Object Enumeration:** Used `Get-MgUserOwnedObject` to efficiently enumerate all directory objects owned by `michael.chen` in a single API call. This is significantly more efficient than iterating all groups and checking ownership individually — fewer API calls means a smaller log footprint and reduced detection surface. Found ownership of multiple groups, including `IT Application Managers`.

3. **Role Discovery on Owned Groups:** Filtered owned groups by `IsAssignableToRole eq true` and checked each for active directory role assignments. Found that `IT Application Managers` held the **Application Administrator** role (tenant-wide scope, `/`).

4. **SP Recon Before Escalating:** Before modifying any group membership, enumerated all role-assignable groups in the tenant holding GA, PAA, or PRA roles. For each such group, queried `/beta/groups/{id}/members` to surface service principal members — necessary because the v1.0 `Get-MgGroupMember` endpoint does not return service principals, creating an auditing blind spot. Found that a group with the **Privileged Authentication Administrator** role had **`Identity Management Portal`** (a service principal) as a member — the end target of the attack chain.

5. **Group Membership Self-Add:** Used the active group ownership to add `michael.chen` directly to `IT Application Managers` via `New-MgGroupMemberByRef`. No approval required — group owners have unconditional control over membership.

6. **Token Refresh:** Disconnected and re-authenticated to obtain a new access token containing the updated group membership claim and inherited Application Administrator role.

7. **Credential Injection on Target SP:** With Application Administrator active, located the `Identity Management Portal` service principal and added a new client secret via `Add-MgServicePrincipalPassword`. Application Administrator can add credentials to **any** enterprise application in the tenant — not just owned ones. Saved the generated secret.

8. **Pivot to Service Principal Context:** Disconnected Michael's session and re-authenticated using the SP's `AppId` and the newly added client secret via `Connect-MgGraph -ClientSecretCredential` (app-only flow). Confirmed the SP context via `Get-MgContext`.

9. **PAA Privileges via Group Membership:** The `Identity Management Portal` SP was a member of a group holding the Privileged Authentication Administrator role — making it a de-facto PAA without a direct role assignment. PAA can reset passwords for any user in the tenant, including Global Administrators.

10. **Account Compromise:** Reset the target administrator's password via `Update-MgUser -PasswordProfile`.

11. **Flag Retrieval:** Disconnected the SP session and authenticated as `EntraGoat-admin-s3` using the reset password (ROPC flow). Issued a Graph call to `/v1.0/me?$select=onPremisesExtensionAttributes` and extracted the flag from `extensionAttribute1`.

## 3. Root Cause Analysis

- **Group Ownership Grants Unconditional Membership Control:** Group owners have full administrative control over group membership with no built-in approval gate. When a role-assignable group is owned by a non-administrative user, that user has an unguarded path to any role the group holds — ownership is functionally equivalent to role assignment.

- **Application Administrator is Tenant-Wide:** The Application Administrator role is frequently granted under the assumption it is limited in scope. In reality it grants credential management rights over every enterprise application and service principal in the tenant — not just owned ones. This makes it one of the most impactful roles for lateral movement to service principal identities.

- **SP-in-Group Indirect Privilege Path:** The `Identity Management Portal` SP held PAA not through a direct role assignment but through group membership. Direct SP role assignments are commonly audited; SP group memberships leading to privileged roles are far less visible and rarely included in privilege mapping exercises.

- **v1.0 API Blind Spot for SP Group Members:** The Microsoft Graph v1.0 `GET /groups/{id}/members` endpoint does not return service principal members — only the `/beta` endpoint exposes them. Standard portal views and many audit tools rely on v1.0, meaning SP memberships in privileged groups are invisible to routine auditing.

- **Enumeration Efficiency as an OPSEC Factor:** Iterating all groups and checking ownership individually generates hundreds to thousands of API calls. `Get-MgUserOwnedObject` retrieves the same result in a single call. In real environments, noisy enumeration increases the chance of detection; understanding which API calls produce equivalent results with minimum queries is both an attacker advantage and a defender signal.

## 4. Mitigation & Remediation

- Enforce PIM for Groups on all role-assignable groups — require MFA step-up and designated approver for any membership or ownership change, eliminating the self-service escalation path.
- Restrict ownership of role-assignable and administratively privileged groups to break-glass accounts or governed service accounts; standard user identities should never own groups with elevated role assignments.
- Treat Application Administrator as a Tier-0 equivalent permission — it grants credential injection rights over every SP in the tenant; scope it narrowly, monitor its use, and alert on any client secret or certificate addition to a service principal immediately following an Application Administrator activation.
- Audit service principal memberships in role-assignable groups explicitly using the `/beta` endpoint or tooling that surfaces SP members; portal views and v1.0 Graph calls omit SP members and will miss these paths.
- Include indirect privilege paths (SP → group → role) in privilege mapping and attack path analysis, not just direct role assignments.
- Monitor and alert on the correlated sequence: group membership self-add → token refresh → `Add-MgServicePrincipalPassword` → SP authentication → admin password reset. Each event is individually low-signal; in sequence they form the complete attack chain.
- Schedule recurring Entra ID Access Reviews covering both group owners and group members for all role-assignable groups.
