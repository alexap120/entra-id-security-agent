import json
import os
import requests
from dotenv import load_dotenv
from msal import ConfidentialClientApplication
from openai import AzureOpenAI

# 1. Load Credentials
load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT")

# Initialize Clients
msal_app = ConfidentialClientApplication(
    CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=f"https://login.microsoftonline.com/{TENANT_ID}",
)

ai_client = AzureOpenAI(
    azure_endpoint=AZURE_OPENAI_ENDPOINT,
    api_key=AZURE_OPENAI_KEY,
    api_version="2024-08-01-preview",
)

def _get_graph_headers():
    token = msal_app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in token:
        raise Exception("Failed to acquire Graph API token")
    return {"Authorization": f"Bearer {token['access_token']}"}

# --- TOOL FUNCTIONS ---

def get_tenant_users():
    """Fetch all users in the tenant."""
    headers = _get_graph_headers()
    res = requests.get("https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled", headers=headers)
    return res.json().get("value", [])

def get_conditional_access_policies():
    """Fetch all Conditional Access Policies in the tenant."""
    headers = _get_graph_headers()
    res = requests.get("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", headers=headers)
    return res.json().get("value", [])

def get_service_principals_and_owners():
    """Retrieves Service Principals and App Registrations that actually have explicitly assigned owners."""
    headers = _get_graph_headers()
    url = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName&$expand=owners"
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        return {"error": res.text}
    
    sps = res.json().get("value", [])
    results = []
    
    for sp in sps:
        owners = sp.get("owners", [])
        if owners:  # Strictly filter ONLY service principals that have designated owners
            owner_details = [{
                "displayName": o.get("displayName"),
                "userPrincipalName": o.get("userPrincipalName")
            } for o in owners]
            
            results.append({
                "servicePrincipalName": sp.get("displayName"),
                "appId": sp.get("appId"),
                "servicePrincipalId": sp.get("id"),
                "owners": owner_details
            })
    return results

def get_directory_roles_and_members():
    """Retrieves Directory Roles (e.g., Global Admin, Privileged Auth Admin) and lists all assigned members (users or service principals)."""
    headers = _get_graph_headers()
    url = "https://graph.microsoft.com/v1.0/directoryRoles?$expand=members"
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        return {"error": res.text}
        
    roles = res.json().get("value", [])
    results = []
    for r in roles:
        members = r.get("members", [])
        if members:
            member_details = [{
                "displayName": m.get("displayName"),
                "userPrincipalName": m.get("userPrincipalName"),
                "objectType": m.get("@odata.type", "").replace("#microsoft.graph.", "")
            } for m in members]
            results.append({
                "roleName": r.get("displayName"),
                "members": member_details
            })
    return results
    
def check_app_certificates_and_permissions():
    """
    Audits Service Principals for active certificate credentials (keyCredentials)
    and checks for high-risk Graph API App Role Assignments like AppRoleAssignment.ReadWrite.All.
    """
    headers = _get_graph_headers()
    url = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,keyCredentials"
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        return {"error": res.text}

    sps = res.json().get("value", [])
    findings = []

    for sp in sps:
        sp_id = sp.get("id")
        display_name = sp.get("displayName")
        app_id = sp.get("appId")
        key_creds = sp.get("keyCredentials", [])
        has_certs = len(key_creds) > 0

        # Query app role assignments granted to this service principal
        roles_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
        roles_res = requests.get(roles_url, headers=headers)
        
        app_role_assignments = []
        if roles_res.status_code == 200:
            app_role_assignments = roles_res.json().get("value", [])

        # Include SPs that have certificates OR active app role assignments
        if has_certs or app_role_assignments:
            findings.append({
                "displayName": display_name,
                "appId": app_id,
                "servicePrincipalId": sp_id,
                "hasCertificates": has_certs,
                "certificateCount": len(key_creds),
                "appRoleAssignments": app_role_assignments
            })

    return findings
    
# Tool Mapping
TOOL_MAP = {
    "get_tenant_users": get_tenant_users,
    "get_conditional_access_policies": get_conditional_access_policies,
    "get_service_principals_and_owners": get_service_principals_and_owners,
    "get_directory_roles_and_members": get_directory_roles_and_members,
    "check_app_certificates_and_permissions": check_app_certificates_and_permissions,
}

# OpenAI Function Schemas
TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "get_tenant_users",
            "description": "Retrieves all user accounts in the Entra ID tenant.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_conditional_access_policies",
            "description": "Retrieves all Conditional Access policies configured in the tenant.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_service_principals_and_owners",
            "description": "Retrieves Service Principals that have explicit owners assigned. Essential for finding non-admin users who own applications.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_directory_roles_and_members",
            "description": "Retrieves directory roles (e.g., Global Admin, Privileged Authentication Admin) and all members assigned to them (including Service Principals).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_app_certificates_and_permissions",
            "description": "Audits all Service Principals for active certificate credentials (keyCredentials) and retrieves their Graph API App Role Assignments (such as AppRoleAssignment.ReadWrite.All).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]

SYSTEM_PROMPT = """You are an expert Microsoft Entra ID Security Auditor.
Your job is to perform deep security audits of tenant configurations, identify misconfigurations, and analyze potential privilege escalation paths.

When evaluating app/service principal ownership:
1. Identify if a non-admin user owns a Service Principal.
2. Check if that Service Principal is assigned a privileged Directory Role (e.g., Privileged Authentication Administrator, Global Administrator).
3. Explain the exact Privilege Escalation Attack Path:
   - A compromised user who owns a Service Principal can add a client secret/password to that Service Principal.
   - The attacker can then authenticate as the Service Principal and inherit its directory role privileges (such as resetting admin passwords or creating TAPs).

Always format your findings clearly:
- Finding
- Attack Vector & Privilege Escalation Path
- Blast Radius & Severity
- Remediation Steps
"""

def chat():
    print("🛡️ Optimized Entra ID Security Agent Initialized! Type 'exit' to quit.\n")
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    while True:
        user_input = input("User: ")
        if user_input.lower() in ["exit", "quit"]:
            break

        messages.append({"role": "user", "content": user_input})

        response = ai_client.chat.completions.create(
            model=AZURE_OPENAI_DEPLOYMENT,
            messages=messages,
            tools=TOOLS_SCHEMA,
            tool_choice="auto",
        )

        response_message = response.choices[0].message

        if response_message.tool_calls:
            messages.append(response_message)

            for tool_call in response_message.tool_calls:
                function_name = tool_call.function.name
                print(f"\n⚙️  [Agent Tool Execution] Running tool: {function_name}()...")

                if function_name in TOOL_MAP:
                    tool_result = TOOL_MAP[function_name]()
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(tool_result),
                    })

            second_response = ai_client.chat.completions.create(
                model=AZURE_OPENAI_DEPLOYMENT,
                messages=messages,
            )
            final_content = second_response.choices[0].message.content
            print(f"\nAgent: {final_content}\n")
            messages.append({"role": "assistant", "content": final_content})
        else:
            print(f"\nAgent: {response_message.content}\n")
            messages.append({"role": "assistant", "content": response_message.content})

if __name__ == "__main__":
    chat()
