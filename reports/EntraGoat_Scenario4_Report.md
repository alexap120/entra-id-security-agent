# 🛡️ EntraGoat Scenario 4: I (Eligibly) Own That

## 1. Executive Summary & Details
* **Target Scenario:** EntraGoat Scenario 4
* **Attacker Identity:** `woody.chen@wwlx355921.onmicrosoft.com`
* **Target Identity:** `EntraGoat-admin-s4@wwlx355921.onmicrosoft.com`
* **Captured Flag:** `EntraGoat{PIM_Gr0up_Pr1v_Esc@l@t10n_2025!}`

---

## 2. Technical Walkthrough & Exploitation
1. **Initial Reconnaissance:** Authenticated via Microsoft Graph PowerShell SDK (`Connect-MgGraph`). Verified standard identity profile without active directory role assignments.
2. **PIM Eligibility Discovery:** Queried Privileged Identity Management (PIM) for Groups using `Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance`. Discovered an eligible **Owner** assignment on the `Application Operations Team` group (`9179f95b-cb13-4b31-9e42-631fd18717ea`).
3. **Privilege Activation:** Navigated to the Microsoft Entra Admin Center (`Identity Governance` -> `Privileged Identity Management` -> `My roles` -> `Groups`) and self-activated the eligible **Owner** role for the `Application Operations Team` group.
4. **Group Membership Escalation:** Utilized active Group Owner rights via PowerShell (`New-MgGroupMember`) to add `woody.chen` directly to the `Application Operations Team` member list.
5. **Token Refresh & Flag Extraction:** Re-authenticated (`Disconnect-MgGraph` / `Connect-MgGraph`) to issue an updated access token containing the new group claim. Queried `EntraGoat-admin-s4` via `Get-MgUser` to successfully extract `extensionAttribute1`.

---

## 3. Root Cause Analysis
* **Flawed PIM Activation Policies:** The PIM for Groups activation policy lacked critical security controls (e.g., Multi-Factor Authentication step-up, explicit approval gates, or ticket requirements), allowing instant self-activation.
* **Group-Based Privilege Inheritance:** The `Application Operations Team` group was assigned elevated directory permissions. Gaining member access to this group automatically granted inherited rights to read privileged user attributes.
* **Overlooked PIM for Groups Governance:** Organizations frequently secure PIM for Directory Roles while leaving PIM for Groups unmonitored, creating a indirect privilege escalation vector.

---

## 4. Mitigation & Remediation
* **Enforce Approval Workflows:** Configure PIM activation policies to require MFA step-up and designated administrative approval for all PIM for Groups assignments.
* **Restrict Group Ownership:** Avoid assigning administrative roles to groups owned by non-administrative users.
* **Implement Just-In-Time (JIT) Access Reviews:** Regularly audit eligible assignments for both Directory Roles and Privileged Access Groups using Entra Access Reviews.
