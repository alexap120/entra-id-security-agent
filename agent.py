import json
import os
from dotenv import load_dotenv
from openai import AzureOpenAI

# Import our upgraded tool suite
from entra_tools import (
    get_tenant_users,
    get_conditional_access_policies,
    get_service_principals_and_owners,
    get_directory_roles_and_members,
    check_app_certificates_and_permissions,
    check_group_ownership_escalations
)

# 1. Load Credentials
load_dotenv()
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT")

# 2. Initialize AI Client
ai_client = AzureOpenAI(
    azure_endpoint=AZURE_OPENAI_ENDPOINT,
    api_key=AZURE_OPENAI_KEY,
    api_version="2024-08-01-preview",
)

# --- SYSTEM PROMPT & SCHEMAS ---

SYSTEM_PROMPT = """You are an elite Microsoft Entra ID Security Auditor.
Your job is to perform deep security audits of tenant configurations, identify misconfigurations, and analyze potential privilege escalation paths.

Always evaluate these core attack vectors:
1. **Service Principal Ownership Abuse:** Non-admin users who own a Service Principal with privileged Directory Roles.
2. **App Role Assignment Abuse:** Service Principals holding high-risk API permissions like 'AppRoleAssignment.ReadWrite.All', especially if they use certificate-based authentication (keyCredentials).
3. **Group Ownership Escalation:** Non-admin users who own groups. Group owners can add themselves as members to inherit any administrative roles or app access granted to that group.

Always format your findings clearly using:
- Finding
- Attack Vector & Privilege Escalation Path
- Blast Radius & Severity
- Remediation Steps
"""

TOOL_MAP = {
    "get_tenant_users": get_tenant_users,
    "get_conditional_access_policies": get_conditional_access_policies,
    "get_service_principals_and_owners": get_service_principals_and_owners,
    "get_directory_roles_and_members": get_directory_roles_and_members,
    "check_app_certificates_and_permissions": check_app_certificates_and_permissions,
    "check_group_ownership_escalations": check_group_ownership_escalations,
}

TOOLS_SCHEMA = [
    {"type": "function", "function": {"name": "get_tenant_users", "description": "Retrieves all user accounts in the Entra ID tenant.", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "get_conditional_access_policies", "description": "Retrieves all Conditional Access policies.", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "get_service_principals_and_owners", "description": "Retrieves Service Principals and explicit owners to find non-admin owners.", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "get_directory_roles_and_members", "description": "Retrieves directory roles and all assigned members.", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "check_app_certificates_and_permissions", "description": "Audits Service Principals for active certificate credentials and dangerous Graph API App Role Assignments (like AppRoleAssignment.ReadWrite.All).", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "check_group_ownership_escalations", "description": "Audits groups to identify Group Ownership Escalation vectors (non-admin users who own groups and can add themselves to inherit privileges).", "parameters": {"type": "object", "properties": {}}}}
]

# --- CHAT EXECUTION LOOP ---

def chat():
    print("🛡️ Elite Entra ID Security Agent Initialized! Type 'exit' to quit.\n")
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
