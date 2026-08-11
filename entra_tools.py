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

def get_tenant_users():
    """Retrieves all users in the Entra ID tenant."""
    headers = _get_headers()
    res = requests.get("https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled", headers=headers)
    return res.json().get("value", []) if res.status_code == 200 else {"error": res.text}

def get_conditional_access_policies():
    """Retrieves all Conditional Access policies configured in the tenant."""
    headers = _get_headers()
    res = requests.get("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", headers=headers)
    return res.json().get("value", []) if res.status_code == 200 else {"error": res.text}

def get_service_principals_and_owners():
    """Retrieves Service Principals and App Registrations with their explicit owners."""
    headers = _get_headers()
    url = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName&$expand=owners"
    res = requests.get(url, headers=headers)
    if res.status_code != 200: return {"error": res.text}
    
    sps = res.json().get("value", [])
    results = []
    for sp in sps:
        owners = sp.get("owners", [])
        if owners:
            owner_details = [{"displayName": o.get("displayName"), "userPrincipalName": o.get("userPrincipalName")} for o in owners]
            results.append({
                "servicePrincipalName": sp.get("displayName"),
                "appId": sp.get("appId"),
                "servicePrincipalId": sp.get("id"),
                "owners": owner_details
            })
    return results

def get_directory_roles_and_members():
    """Retrieves Directory Roles and all assigned members (users or service principals)."""
    headers = _get_headers()
    url = "https://graph.microsoft.com/v1.0/directoryRoles?$expand=members"
    res = requests.get(url, headers=headers)
    if res.status_code != 200: return {"error": res.text}
        
    roles = res.json().get("value", [])
    results = []
    for r in roles:
        members = r.get("members", [])
        if members:
            member_details = [{"displayName": m.get("displayName"), "userPrincipalName": m.get("userPrincipalName", "N/A"), "objectType": m.get("@odata.type", "").replace("#microsoft.graph.", "")} for m in members]
            results.append({
                "roleName": r.get("displayName"),
                "members": member_details
            })
    return results

def check_app_certificates_and_permissions():
    """Queries Service Principals for active certificates and Graph API App Role Assignments."""
    headers = _get_headers()
    url = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,keyCredentials"
    res = requests.get(url, headers=headers)
    if res.status_code != 200: return {"error": res.text}

    sps = res.json().get("value", [])
    findings = []
    for sp in sps:
        sp_id = sp.get("id")
        key_creds = sp.get("keyCredentials", [])
        has_certs = len(key_creds) > 0

        roles_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
        roles_res = requests.get(roles_url, headers=headers)
        app_role_assignments = roles_res.json().get("value", []) if roles_res.status_code == 200 else []

        if has_certs or app_role_assignments:
            findings.append({
                "displayName": sp.get("displayName"),
                "appId": sp.get("appId"),
                "hasCertificates": has_certs,
                "certificateCount": len(key_creds),
                "appRoleAssignments": app_role_assignments
            })
    return findings

def check_group_ownership_escalations():
    """Audits groups to find non-admin owners who could escalate privileges by adding themselves to role-assignable groups."""
    headers = _get_headers()
    url = "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,isAssignableToRole&$expand=owners,members"
    res = requests.get(url, headers=headers)
    if res.status_code != 200: return {"error": res.text}
        
    groups = res.json().get("value", [])
    findings = []
    
    for g in groups:
        owners = g.get("owners", [])
        if owners:
            owner_details = [{"displayName": o.get("displayName"), "userPrincipalName": o.get("userPrincipalName", "N/A")} for o in owners]
            findings.append({
                "groupName": g.get("displayName"),
                "groupId": g.get("id"),
                "isAssignableToRole": g.get("isAssignableToRole", False),
                "owners": owner_details,
                "memberCount": len(g.get("members", []))
            })
    return findings
