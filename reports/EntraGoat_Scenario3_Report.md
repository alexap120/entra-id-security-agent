# 🛡️ EntraGoat Scenario 3: Group MemberShipwreck

## 1. Setup & Overview
* **Attacker Account:** `michael.chen@wwlx355921.onmicrosoft.com`
* **Target Account:** `EntraGoat-admin-s3@wwlx355921.onmicrosoft.com`
* **Captured Flag:** `EntraGoat{Gr0up_Ch@1n_Pr1v_Esc@l@t10n!}`

## 2. Technical Walkthrough & Exploitation
1. **Enumeration:** Authenticated as `michael.chen` via PowerShell using `Connect-MgGraph`.
2. **Privilege Discovery:** Queried owned objects via `Get-MgUserOwnedObject` and identified ownership of the `IT Application Managers` group (`71c6b8af-3901-444e-8ff7-d4d64af843e3`).
3. **Group Ownership Abuse:** Executed `New-MgGroupMember` to add `michael.chen` to the `IT Application Managers` group.
4. **Token Refresh:** Re-authenticated (`Disconnect-MgGraph` / `Connect-MgGraph`) to issue a new access token containing the updated group membership claims.
5. **Flag Extraction:** Extracted `extensionAttribute1` from `EntraGoat-admin-s3`.

## 3. The Why (Root Cause Analysis)
* **Unmonitored Group Ownership:** Group owners hold full administrative control over group membership. If a group is assigned elevated administrative permissions or roles, any owner of that group can unilaterally elevate their own privileges by adding themselves as a member.
* **API vs. UI Security Boundary:** Bypassing web portal restrictions via direct Microsoft Graph API calls allows unprivileged portal users to perform administrative actions if underlying object permissions permit it.

## 4. The Fix (Remediation)
* **Privileged Group Governance:** Require **Privileged Identity Management (PIM) for Groups** so group owners must request justification and approval before modifying memberships of sensitive groups.
* **Restricted Group Ownership:** Ensure role-assignable groups or administrative groups are owned strictly by break-glass accounts or governed service accounts rather than standard user identities.
* **Access Reviews:** Schedule recurring Entra ID Access Reviews to audit group owners and members regularly.
