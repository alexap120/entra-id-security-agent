# 🛡️ Microsoft Entra ID AI Security Agent

An autonomous identity security auditing agent built using Python, Azure OpenAI (`gpt-4o`), MSAL, and Microsoft Graph API. The agent uses function calling to query tenant configurations and detect privilege escalation vectors in environments like **EntraGoat**.

## 🚀 Key Capabilities
* Live Graph API execution loop for tenant auditing.
* Data pre-processing to minimize context usage.
* Automated detection of non-admin app ownership and elevated directory roles.

## 🛠️ How to Run
1. Clone the repository and install dependencies:
   ```bash
   pip install -r requirements.txt
2. Copy .env.example to .env and fill in credentials.
3. Run the agent:
   ```bash
   python agent.py
