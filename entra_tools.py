import os
import requests
from dotenv import load_dotenv
from msal import ConfidentialClientApplication

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

app = ConfidentialClientApplication(
    CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=f"https://login.microsoftonline.com/{TENANT_ID}"
)

def _get_headers():
    token_result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in token_result:
        raise Exception(f"Failed to get token: {token_result.get('error_description')}")
    return {"Authorization": f"Bearer {token_result['access_token']}"}

def get_users():
    """Retrieves all users in the Entra ID tenant."""
    headers = _get_headers()
    res = requests.get("https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled", headers=headers)
    return res.json().get("value", []) if res.status_code == 200 else {"error": res.text}

def get_global_admins():
    """Retrieves all members assigned to the Global Administrator role."""
    headers = _get_headers()
    # Fetch roles to get Global Admin template ID
    roles_res = requests.get("https://graph.microsoft.com/v1.0/directoryRoles", headers=headers).json()
    ga_role = next((r for r in roles_res.get("value", []) if r.get("displayName") == "Global Administrator"), None)
    
    if not ga_role:
        return {"message": "Global Administrator role not activated or found."}
    
    members_res = requests.get(f"https://graph.microsoft.com/v1.0/directoryRoles/{ga_role['id']}/members", headers=headers)
    return members_res.json().get("value", []) if members_res.status_code == 200 else {"error": members_res.text}

def get_conditional_access_policies():
    """Retrieves all Conditional Access policies configured in the tenant."""
    headers = _get_headers()
    res = requests.get("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", headers=headers)
    return res.json().get("value", []) if res.status_code == 200 else {"error": res.text}
    
def check_app_certificates_and_permissions(graph_client):
    """
    Queries Service Principals for active certificate credentials (keyCredentials)
    and inspects their Graph API App Role Assignments.
    """
    # 1. Get service principals with keyCredentials and appRoleAssignments
    # Query Graph endpoint: /servicePrincipals?$select=id,appId,displayName,keyCredentials
    sps = graph_client.get("/servicePrincipals?$select=id,appId,displayName,keyCredentials")
    
    results = []
    for sp in sps.get("value", []):
        has_certs = len(sp.get("keyCredentials", [])) > 0
        
        # 2. Get App Role Assignments (API permissions like AppRoleAssignment.ReadWrite.All)
        app_roles = graph_client.get(f"/servicePrincipals/{sp['id']}/appRoleAssignments")
        
        roles_list = [role.get("principalDisplayName") for role in app_roles.get("value", [])]
        
        if has_certs or any("AppRoleAssignment" in r for r in roles_list):
            results.append({
                "displayName": sp["displayName"],
                "appId": sp["appId"],
                "hasCertificates": has_certs,
                "appRoleAssignments": app_roles.get("value", [])
            })
            
    return results
