# 🛡️ Entra ID Security Audit Report: EntraGoat Scenario 1

## Executive Summary
An automated AI-driven identity audit was performed against the Microsoft Entra ID tenant. The audit identified a critical privilege escalation path involving non-admin application ownership and elevated directory roles.

## Findings & Vulnerability Analysis
* **Target Application:** `Finance Analytics Dashboard`
* **App/Service Principal ID:** `6edbbe06-8cb0-43bb-859d-e1b83813b143`
* **Assigned Owner:** `David Martinez` (`david.martinez@wwlx355921.onmicrosoft.com`) — *Non-Admin User*
* **Assigned Directory Role:** `Privileged Authentication Administrator`

## Attack Vector & Privilege Escalation Path
1. **Initial Access:** An attacker compromises the account of regular user `David Martinez`.
2. **Credential Injection:** Because David is an explicit owner of the `Finance Analytics Dashboard` Service Principal, he can add a new client secret or certificate credential to the application.
3. **Privilege Escalation:** The attacker authenticates as the Service Principal, inheriting the `Privileged Authentication Administrator` role.
4. **Tenant Takeover:** Using this role, the attacker resets passwords for higher-privileged administrative accounts or creates Temporary Access Passes (TAPs) to fully compromise the directory.

## Severity & Recommendation
* **Severity:** **CRITICAL**
* **Remediation:** Remove non-admin ownership, evaluate/revoke unnecessary directory roles, and enforce ownership guardrails.
