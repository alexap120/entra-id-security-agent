# 🛡️ EntraGoat Scenario 5: Department of Escalations

## 1. Executive Summary & Details

- **Target Scenario:** EntraGoat Scenario 5
- **Attacker Identity:** `sarah.connor@wwlx355921.onmicrosoft.com`
- **Target Identity:** `EntraGoat-admin-s5@wwlx355921.onmicrosoft.com`
- **Captured Flag:** `EntraGoat{Dyn@m1c_AU_P01s0n1ng_FTW!}`

## 2. Technical Walkthrough & Exploitation

1. **Initial Reconnaissance:** Authenticated as Sarah Connor and enumerated current group memberships and PIM-eligible assignments. Discovered four eligible assignments: eligible membership in `HR Support Team` and eligible ownership of `Regional HR Coordinators`, among others.

2. **Privileged Group Discovery:** Enumerated the directory role assignments for each eligible group. Found that `Regional HR Coordinators` held the `Privileged Authentication Administrator` (PAA) role — a role that can reset passwords and modify authentication methods for non-admin users.

3. **PIM Activation & Group Self-Add:** Activated the eligible ownership of `Regional HR Coordinators` (8-hour duration, self-service, freetext justification). After activation, added Sarah as a direct member of the group via `New-MgGroupMemberByRef`.

4. **Dead End — 403 on Password Reset:** Immediately attempted to reset the target administrator's password using the inherited PAA role — received a `403 Authorization_RequestDenied`. This was the signal to investigate the role's *scope*, not just its existence.

5. **Role Scope Enumeration:** Queried `Get-MgRoleManagementDirectoryRoleAssignment` with a filter on the group's principal ID and checked `DirectoryScopeId`. Found the PAA role was scoped to `/administrativeUnits/[AU-ID]` rather than `/` (tenant-wide) — meaning it only applied to users *inside* that specific Administrative Unit.

6. **AU Membership Rule Discovery:** Fetched the AU object and inspected its properties. Found:
   - `MembershipType: Dynamic`
   - `MembershipRuleProcessingState: On`
   - `MembershipRule: (user.department -eq "HR")`

   The AU's membership was fully driven by the `department` user attribute — a value that can be modified by anyone with a user-update permission.

7. **Permission Discovery — Second Group:** Turned attention to `HR Support Team`. Checked its role assignment *and* its scope: role was `User Profile Administrator` (a custom role), scoped to `/` (tenant-wide). Enumerated the custom role's `AllowedResourceActions` and confirmed `microsoft.directory/users/basic/update` — sufficient to modify user attributes including `department`.

8. **PIM Activation — Support Team Membership:** Self-activated the eligible membership in `HR Support Team` (8-hour duration). Refreshed the token to pick up the new permissions.

9. **Attribute Manipulation:** Called `Update-MgUser` to change the target administrator's `department` attribute to `"HR"`. Verified the change was applied by re-reading the attribute.

10. **Dynamic AU Processing:** Waited for Entra ID's dynamic membership engine to evaluate the updated attribute. Polled `Get-MgDirectoryAdministrativeUnitMember` until the target administrator appeared in the AU — dynamic processing can take several minutes.

11. **Privilege Scope Now Covers the Target:** With the administrator now a member of the AU, the PAA role held by `Regional HR Coordinators` (and by extension Sarah) became applicable to that account.

12. **Account Compromise:** Reset the target administrator's password via `Update-MgUser -PasswordProfile`. Authenticated as the compromised account using the new password (ROPC flow).

13. **Flag Retrieval:** Issued a Graph API call for `onPremisesExtensionAttributes` on the current user (`/v1.0/me?$select=onPremisesExtensionAttributes`) and extracted the flag from `extensionAttribute1`.

## 3. Root Cause Analysis

- **Attribute Trust Without Restriction:** The dynamic AU membership rule relied on the `department` attribute, which any user with `microsoft.directory/users/basic/update` could freely modify — including support-tier users. The system trusted that attribute values were authoritative, with no controls on who could write them.

- **Scope Blindness on Privileged Role Assignments:** The PAA role appeared powerful on initial enumeration but was scoped to a single AU. The attack only became possible because that AU's membership boundary was itself manipulable — a combination invisible without checking both the role scope *and* the AU's membership mechanism.

- **Controllable Group Held a Privileged Role:** The `Regional HR Coordinators` group held the PAA role, but its ownership could be self-activated via PIM with no approval requirement and a freetext justification. Group owners can add members, so ownership eligibility effectively granted a path to group membership and thus the role.

- **PIM Eligibility Chains:** Two separate PIM eligibilities — one for group membership, one for group ownership — combined into an escalation path that neither grant would have enabled individually. Eligible ownership is often overlooked as a privilege; it enables full group membership management after a simple self-activation.

- **Dynamic AUs as a False Security Boundary:** AU-scoped roles are often assumed to provide safe delegation. When the AU's membership is driven by a user-modifiable attribute, the apparent scope restriction becomes meaningless — the attacker controls who is in scope.

## 4. Mitigation & Remediation

- Restrict modification of attributes that feed dynamic Administrative Unit membership rules — treat `department`, `jobTitle`, and similar fields as security-sensitive when they govern AU membership, and scope write permissions accordingly.
- Audit all dynamic AU membership rules and map which roles they scope — then identify who can write the attributes those rules evaluate.
- Require approval and MFA step-up for PIM activations that grant group ownership, not just membership; group ownership is functionally equivalent to a membership escalation path.
- Avoid assigning privileged roles (especially PAA) to groups whose membership or ownership can be reached through PIM self-activation without approvals.
- When evaluating a role assignment, always verify its `DirectoryScopeId` — a role scoped to an AU is only as restricted as the AU's own membership controls.
- Monitor `department` (and other AU-rule attributes) for unexpected changes, especially on accounts holding privileged directory roles; alert on changes that move a privileged account into a scope covered by a high-impact role assignment.
- Correlate PIM group activations, attribute modifications, and AU membership changes as a detection sequence — each event is individually low-signal, but in sequence they form the complete attack chain.
