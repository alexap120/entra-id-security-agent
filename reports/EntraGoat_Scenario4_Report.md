# 🛡️ EntraGoat Scenario 4: I (Eligibly) Own That

## 1. Executive Summary & Details

- **Target Scenario:** EntraGoat Scenario 4
- **Attacker Identity:** `woody.chen@wwlx355921.onmicrosoft.com`
- **Target Identity:** `EntraGoat-admin-s4@wwlx355921.onmicrosoft.com`
- **Captured Flag:** `EntraGoat{PIM_Gr0up_Pr1v_Esc@l@t10n_2025!}`

## 2. Technical Walkthrough & Exploitation

1. **Initial Reconnaissance:** Authenticated as `woody.chen` via `Connect-MgGraph`. Confirmed no active directory role assignments, no current group memberships beyond defaults, and no owned directory objects.

2. **PIM Eligibility Discovery:** Queried `identityGovernance/privilegedAccess/group/eligibilitySchedules` and found a single eligible assignment: eligible *owner* of the `Application Operations Team` group.

3. **Group Role Enumeration:** Checked the group's active directory role assignments (`Get-MgRoleManagementDirectoryRoleAssignment`) — none found. Checked its *eligible* role assignments (`Get-MgRoleManagementDirectoryRoleEligibilitySchedule`) and found: **eligible `Application Administrator`** (tenant-wide scope, `/`).

4. **SP Recon Before Activating Anything:** Before generating any PIM activation noise, enumerated all role-assignable groups holding GA, PAA, or PRA roles across the tenant. For each such group, queried `/beta/groups/{id}/members` (the `/beta` endpoint is required — the v1.0 `Get-MgGroupMember` does not return service principal members, creating an auditing blind spot). Found that the `Global Infrastructure Team` group held the **Global Administrator** role and had **`Infrastructure Monitoring Tool`** (a service principal) as a member — the end target of the attack chain.

5. **PIM Activation — Group Ownership:** Self-activated the eligible owner assignment for `Application Operations Team` (8-hour duration, freetext justification) via `POST .../identityGovernance/privilegedAccess/group/assignmentScheduleRequests`.

6. **Group Membership Self-Add:** Using the now-active ownership, added `woody.chen` as a direct member of `Application Operations Team` via `New-MgGroupMemberByRef`. Refreshed the token to pick up the new group claim.

7. **PIM Activation — Application Administrator Role:** The group's *eligible* Application Administrator role was not automatically active upon joining — it required a separate PIM activation. Posted a `roleAssignmentScheduleRequests` to the *directory roles* endpoint (not the group endpoint, since this is now Woody's own eligible role assignment inherited through membership) to self-activate Application Administrator tenant-wide. Verified the active assignment via `Get-MgRoleManagementDirectoryRoleAssignment`.

8. **Credential Backdoor on Target SP:** With Application Administrator active, located the `Infrastructure Monitoring Tool` service principal and added a new client secret via `Add-MgServicePrincipalPassword`. Saved the generated secret for the next step.

9. **Pivot to Service Principal Context:** Disconnected the Woody session and re-authenticated using the SP's `AppId` and the newly added client secret via `Connect-MgGraph -ClientSecretCredential` (app-only flow). Confirmed the SP context via `Get-MgContext`.

10. **GA Privileges via Group Membership:** The SP was a member of `Global Infrastructure Team`, which held the Global Administrator role — making the SP a de-facto Global Administrator. Confirmed by successfully querying and modifying the target admin account.

11. **Account Compromise:** Reset the target administrator's password via `Update-MgUser -PasswordProfile`. As an alternative path, also available: issuing a **Temporary Access Pass** (TAP) via `New-MgUserAuthenticationTemporaryAccessPassMethod` — a time-limited passcode usable to authenticate without MFA, useful when the admin account has MFA enforced.

12. **Flag Retrieval:** Disconnected the SP session and authenticated as `EntraGoat-admin-s4` using the reset password (ROPC flow). Issued a Graph call to `/v1.0/me?$select=onPremisesExtensionAttributes` and extracted the flag from `extensionAttribute1`.

## 3. Root Cause Analysis

- **PIM Eligibility for Group Ownership:** Eligible group ownership is often overlooked compared to eligible role assignments, but the effect is equivalent — after a simple self-activation with a freetext justification, an owner can freely manage group membership, turning ownership eligibility into a full membership escalation path.

- **Eligible Role on a Group (Double-Hop PIM):** The `Application Operations Team` group held an *eligible* Application Administrator role, not an active one. This required a second PIM activation step — but both activations were self-service with no approval required, chaining two escalations with no friction.

- **Application Administrator Credential Injection:** Application Administrator can add credentials (secrets and certificates) to any enterprise application in the tenant. This is frequently underestimated as a privilege — it effectively grants the ability to impersonate any service principal, inheriting all permissions and group memberships that SP holds.

- **SP-in-Group GA Inheritance:** The `Infrastructure Monitoring Tool` SP held Global Administrator not through a direct role assignment but through group membership in `Global Infrastructure Team`. Direct SP role assignments are commonly audited; SP group memberships leading to privileged roles are far less visible and harder to detect.

- **v1.0 API Blind Spot for SP Group Members:** The Microsoft Graph v1.0 `GET /groups/{id}/members` endpoint does not return service principal members — only the `/beta` endpoint does. This means standard tooling and portal views may not surface SP membership in privileged groups, leaving the attack path invisible to routine auditing.

- **No Approval or MFA on PIM Activations:** Both PIM activations (group ownership and Application Administrator) required only a freetext justification — no MFA step-up, no approver, no ticket reference. This allowed the full chain to execute silently.

## 4. Mitigation & Remediation

- Require MFA step-up and designated approver for all PIM activations — both directory role assignments *and* PIM for Groups (ownership and membership), as both are equally capable of privilege escalation.
- Treat eligible group ownership as equivalent in sensitivity to eligible group membership — an owner can self-promote to member at any time after activation.
- Audit service principal memberships in role-assignable groups explicitly using the `/beta` endpoint or tooling that surfaces SP members; do not rely on portal views or v1.0 Graph calls, which omit SP members.
- Limit Application Administrator assignments — consider whether any identity needs this role, and if so, scope it and monitor its use; treat any client secret addition to a high-privilege SP as a critical alert.
- Enumerate indirect GA/PAA/PRA paths regularly: direct role assignments to SPs are not the only path — SP group memberships must be included in privilege mapping.
- Alert on: PIM group ownership activations, group membership changes immediately following a PIM activation, client secret additions to service principals, and SP authentication events using newly added credentials — as a correlated sequence these form the complete attack chain.
- Implement Access Reviews for PIM for Groups eligible assignments on a regular cadence, not just for directory role eligibilities.
