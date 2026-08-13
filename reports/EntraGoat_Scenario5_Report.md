# 🛡️ EntraGoat Scenario 5: Department of Escalations

## 1. Executive Summary & Details

- **Target Scenario:** EntraGoat Scenario 5
- **Attacker Identity:** `sarah.connor@wwlx355921.onmicrosoft.com`
- **Target Identity:** `EntraGoat-admin-s5@wwlx355921.onmicrosoft.com`
- **Captured Flag:** `EntraGoat{Dyn@m1c_AU_P01s0n1ng_FTW!}`

---

## 2. Technical Walkthrough & Exploitation

1. **Initial Reconnaissance:** Authenticated as Sarah Connor and enumerated PIM Group eligibilities. Discovered eligible membership in `HR Support Team` and eligible ownership of `Regional HR Coordinators`.

2. **Privileged Group Discovery:** Identified that `Regional HR Coordinators` held the **Privileged Authentication Administrator** role, but the role was scoped to the `HR Department` Administrative Unit rather than the entire tenant.

3. **PIM Activation & Group Escalation:** Activated the eligible ownership of `Regional HR Coordinators` and added Sarah as a member, inheriting the group's privileged role.

4. **Dynamic AU Enumeration:** Investigated the `HR Department` Administrative Unit and discovered a dynamic membership rule:
   `(user.department -eq "HR")`

5. **Attribute Manipulation:** Activated Sarah's eligible membership in `HR Support Team`, which provided the custom **User Profile Administrator** role with `microsoft.directory/users/basic/update`. Used this permission to change the target administrator's `department` attribute to `HR`.

6. **Privilege Scope Manipulation:** The dynamic Administrative Unit processed the attribute change and automatically added the target administrator to the `HR Department` AU. Because the attacker's group had **Privileged Authentication Administrator** scoped to this AU, the attacker gained password-reset capability over the target.

7. **Account Compromise:** Reset the target administrator's password, authenticated as the compromised account, and retrieved the flag from `extensionAttribute1`.

---

## 3. Root Cause Analysis

- **Overly Broad Attribute Modification:** `User Profile Administrator` allowed users to modify attributes that influenced security-sensitive dynamic membership.
- **Privilege Assigned to Controllable Group:** A highly privileged role was assigned to a group whose membership/ownership could be manipulated through PIM.
- **Dynamic AU as a Security Boundary:** The AU relied on the user-controlled `department` attribute to determine privileged scope.
- **Privilege Chaining:** Individually limited permissions combined to create an escalation path from a support account to administrator-level access.

---

## 4. Mitigation & Remediation

- Restrict modification of attributes used in dynamic Administrative Unit membership rules.
- Review and minimize PIM eligibility for privileged groups, particularly group ownership.
- Require MFA and approval for privileged PIM Group activations.
- Avoid assigning highly privileged roles to groups that can be controlled by lower-privileged users.
- Review dynamic Administrative Units for privilege-escalation paths based on user-modifiable attributes.
- Monitor changes to security-sensitive attributes such as `department` when they affect privileged AU membership.
