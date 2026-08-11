# 🛡️ EntraGoat Scenario X: [Scenario Name]

## 1. Setup & Initial Findings
* **Credentials Provided:** `username@tenant.onmicrosoft.com`
* **Target:** [Target User/Service Principal/Resource]
* **Hint Provided:** "[Insert scenario hint here]"

## 2. Technical Walkthrough (Step-by-Step)
1. **Reconnaissance:** Ran `agent.py` / PowerShell query to inspect permissions.
   * *Insert screenshot of agent or Graph output here:* `![Recon](./assets/scenarioX_recon.png)`
2. **Exploitation / Discovery:** [Detailed steps on how the flaw was identified or exploited]
   * *Insert portal/CLI screenshot here:* `![Exploit](./assets/scenarioX_exploit.png)`

## 3. The Why (Underlying Flaw)
* **Root Cause:** [Explain the specific Entra ID misconfiguration, e.g., over-privileged Managed Identity, weak CA policy, dangerous role assignment].
* **Impact:** [What an attacker can achieve].

## 4. The Fix (Remediation)
* **Immediate Fix:** [How to revoke access / fix the setting in Portal or via Graph API].
* **Long-term Defense:** [Governance policies or guardrails to prevent this in production].
