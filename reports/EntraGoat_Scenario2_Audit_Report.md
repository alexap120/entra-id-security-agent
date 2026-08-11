# Graph Me the Crown (and Roles) — EntraGoat Writeup

## 1. Challenge Overview & Flag

- **Scenario Name:** Graph Me the Crown (and Roles)
- **Target Admin:** `EntraGoat-admin-s2@wwlx355921.onmicrosoft.com`
- **Captured Flag:** `EntraGoat{4P1_P37mission_4bus3_Succ3ss!}`

## 2. Step-by-Step Walkthrough

1. **Credential Discovery:** Decoded the leaked Base64 `.pfx` certificate string from the CI/CD build output and saved it as `cert.pfx`.
2. **Identity Resolution:** Inspected the certificate subject (`CN=Corporate Finance Analytics`) and queried the Graph API to resolve its `AppId` (`03d55947-c832-4e1e-9f04-3f1cd25ad3c6`).
3. **Authentication:** Authenticated as the application via certificate-based client credentials (`AppOnly` context).
4. **Privilege Escalation:** Exploited the standing `AppRoleAssignment.ReadWrite.All` permission to grant the application `User.Read.All` without admin consent.
5. **Flag Extraction:** Re-authenticated with the updated token scope and read `extensionAttribute1` on the target admin user.

## 3. "The Why" (Root Cause Analysis)

- **Certificate Exposure:** Hardcoded/logged certificate private keys in build output bypass standard interactive authentication controls.
- **Over-Privileged Identity:** Holding `AppRoleAssignment.ReadWrite.All` creates an administrative bypass where an application can self-grant any Graph API permission in the tenant.

## 4. "The Fix" (Remediation Steps)

- **Revoke Credentials:** Immediately delete the compromised certificate thumbprint in Entra ID under App Registrations → Corporate Finance Analytics → Certificates & secrets.
- **Enforce Least Privilege:** Remove `AppRoleAssignment.ReadWrite.All` and restrict permissions to only what the application explicitly requires.
- **Log Sanitization & Secret Scanning:** Implement pipeline security tools (e.g., Gitleaks) to detect and redact certificate keys in STDOUT/build logs.
