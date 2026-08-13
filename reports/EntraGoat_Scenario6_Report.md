# 🛡️ EntraGoat Scenario 6: CBA Root Access

## 1. Executive Summary & Details

* **Target Scenario:** EntraGoat Scenario 6
* **Attacker Identity:** `Legacy-Automation-Service`
* **Target Identity:** `EntraGoat-admin-s6@wwlx355921.onmicrosoft.com`
* **Captured Flag:** `EntraGoat{C3rt_Byp@ss_R00t3d_4dm1n}`

---

## 2. Technical Walkthrough & Exploitation

1. **Credential Discovery:** Identified a hardcoded client secret in the legacy `legacy_sync_task.ps1` script for `Legacy-Automation-Service`.

2. **Application Authentication:** Used the client ID, client secret, and tenant ID to obtain a Microsoft Graph access token through the OAuth2 client-credentials flow.

3. **Token Analysis:** Decoded the access token and identified the `Application.ReadWrite.OwnedBy` and `Directory.Read.All` application permissions.

4. **Application Ownership Discovery:** Enumerated applications owned by `Legacy-Automation-Service` and discovered `DataSync-Production`.

5. **Privilege Discovery:** Enumerated `DataSync-Production`'s Microsoft Graph app-role assignments and identified:

   * `Directory.Read.All`
   * `Organization.ReadWrite.All`

6. **Privilege Escalation:** The combination of application ownership and privileged Graph permissions provided a path to perform sensitive directory operations and access the target administrator account.

7. **Flag Retrieval:** Accessed the target `EntraGoat Administrator S6` account and retrieved the flag from `extensionAttribute1`.

---

## 3. Root Cause Analysis

* **Hardcoded Credentials:** A client secret was stored directly in a PowerShell script.
* **Excessive Application Permissions:** The automation service had `Application.ReadWrite.OwnedBy`, allowing it to modify applications under its ownership.
* **Privileged Permission Chaining:** `DataSync-Production` possessed highly privileged Microsoft Graph permissions.
* **Excessive Application Ownership:** A compromised service principal was able to control another application with elevated privileges.

---

## 4. Mitigation & Remediation

* Remove hardcoded secrets from source code and store credentials in a secure secret-management solution.
* Rotate and revoke exposed client secrets immediately.
* Apply least-privilege permissions to service principals and applications.
* Review application ownership and remove unnecessary service-principal owners.
* Avoid privilege chains where lower-privileged applications can control applications with administrative permissions.
* Monitor service-principal authentication, application modifications, ownership changes, and permission assignments.

