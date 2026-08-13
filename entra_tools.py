import os
import requests

from dotenv import load_dotenv
from msal import ConfidentialClientApplication


# ============================================================
# 1. CONFIGURATION
# ============================================================

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")


if not TENANT_ID:
    raise ValueError("TENANT_ID is not set.")

if not CLIENT_ID:
    raise ValueError("CLIENT_ID is not set.")

if not CLIENT_SECRET:
    raise ValueError("CLIENT_SECRET is not set.")


GRAPH_V1 = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


app = ConfidentialClientApplication(
    CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=f"https://login.microsoftonline.com/{TENANT_ID}",
)


# ============================================================
# 2. AUTHENTICATION
# ============================================================

def _get_headers():
    """
    Obtain an application-only Microsoft Graph access token.
    """

    token_result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )

    if "access_token" not in token_result:
        raise Exception(
            "Failed to obtain Microsoft Graph token: "
            + token_result.get("error_description", "Unknown error")
        )

    return {
        "Authorization": f"Bearer {token_result['access_token']}",
        "Content-Type": "application/json",
    }


# ============================================================
# 3. GENERIC GRAPH HELPERS
# ============================================================

def _get(url, headers=None):
    """
    Simple GET request with error handling.
    """

    if headers is None:
        headers = _get_headers()

    response = requests.get(
        url,
        headers=headers,
        timeout=30,
    )

    if response.status_code != 200:
        return {
            "error": response.text,
            "status_code": response.status_code,
            "url": url,
        }

    return response.json()


def _get_all(url, headers=None):
    """
    Retrieve all Graph pages using @odata.nextLink.
    """

    if headers is None:
        headers = _get_headers()

    results = []

    next_url = url

    while next_url:

        response = requests.get(
            next_url,
            headers=headers,
            timeout=30,
        )

        if response.status_code != 200:
            return {
                "error": response.text,
                "status_code": response.status_code,
                "url": next_url,
            }

        data = response.json()

        results.extend(
            data.get("value", [])
        )

        next_url = data.get("@odata.nextLink")

    return results


def _get_object_name(object_id, headers=None):
    """
    Resolve a directory object ID to a useful display name.

    Used when Graph returns only principalId/groupId/etc.
    """

    if not object_id:
        return None

    if headers is None:
        headers = _get_headers()

    url = (
        f"{GRAPH_V1}/directoryObjects/{object_id}"
        "?$select=id,displayName,userPrincipalName"
    )

    response = requests.get(
        url,
        headers=headers,
        timeout=30,
    )

    if response.status_code != 200:
        return None

    data = response.json()

    return {
        "id": data.get("id"),
        "displayName": data.get("displayName"),
        "userPrincipalName": data.get("userPrincipalName"),
        "objectType": data.get("@odata.type", "")
        .replace("#microsoft.graph.", ""),
    }


# ============================================================
# 4. USERS
# ============================================================

def get_tenant_users():
    """
    Retrieves tenant users and security-relevant attributes.

    Includes:
    - ID
    - Display name
    - UPN
    - User type
    - Account status
    - Department
    - Job title
    - Mail
"""

    headers = _get_headers()

    url = (
        f"{GRAPH_V1}/users"
        "?$select="
        "id,"
        "displayName,"
        "userPrincipalName,"
        "userType,"
        "accountEnabled,"
        "department,"
        "jobTitle,"
        "mail"
    )

    users = _get_all(url, headers)

    if isinstance(users, dict) and "error" in users:
        return users

    return users


# ============================================================
# 5. CONDITIONAL ACCESS
# ============================================================

def get_conditional_access_policies():
    """
    Retrieves Conditional Access policies.
    """

    headers = _get_headers()

    url = (
        f"{GRAPH_V1}/identity/conditionalAccess/policies"
    )

    policies = _get_all(url, headers)

    if isinstance(policies, dict) and "error" in policies:
        return policies

    results = []

    for policy in policies:

        results.append({
            "id": policy.get("id"),
            "displayName": policy.get("displayName"),
            "state": policy.get("state"),
            "conditions": policy.get("conditions"),
            "grantControls": policy.get("grantControls"),
            "sessionControls": policy.get("sessionControls"),
        })

    return results


# ============================================================
# 6. SERVICE PRINCIPALS + OWNERS
# ============================================================

def get_service_principals_and_owners():
    """
    Retrieves service principals and their explicit owners.

    Useful for identifying:
        User
        ↓
        Service Principal ownership
        ↓
        Privileged application
"""

    headers = _get_headers()

    url = (
        f"{GRAPH_V1}/servicePrincipals"
        "?$select=id,appId,displayName,accountEnabled"
    )

    service_principals = _get_all(url, headers)

    if isinstance(service_principals, dict) and "error" in service_principals:
        return service_principals

    results = []

    for sp in service_principals:

        sp_id = sp.get("id")

        owners_url = (
            f"{GRAPH_V1}/servicePrincipals/{sp_id}/owners"
            "?$select=id,displayName,userPrincipalName"
        )

        owners = _get_all(
            owners_url,
            headers,
        )

        if isinstance(owners, dict):
            owners = []

        owner_details = []

        for owner in owners:

            owner_details.append({
                "id": owner.get("id"),
                "displayName": owner.get("displayName"),
                "userPrincipalName": owner.get(
                    "userPrincipalName"
                ),
                "objectType": owner.get(
                    "@odata.type",
                    ""
                ).replace(
                    "#microsoft.graph.",
                    ""
                ),
            })

        if owner_details:

            results.append({
                "servicePrincipalId": sp_id,
                "servicePrincipalName":
                    sp.get("displayName"),
                "appId": sp.get("appId"),
                "accountEnabled":
                    sp.get("accountEnabled"),
                "owners": owner_details,
            })

    return results


# ============================================================
# 7. DIRECTORY ROLES
# ============================================================

def get_directory_roles_and_members():
    """
    Retrieves directory roles and their members.
    """

    headers = _get_headers()

    url = (
        f"{GRAPH_V1}/directoryRoles"
        "?$expand=members"
    )

    roles = _get_all(url, headers)

    if isinstance(roles, dict) and "error" in roles:
        return roles

    results = []

    for role in roles:

        members = role.get("members", [])

        member_details = []

        for member in members:

            member_details.append({
                "id": member.get("id"),
                "displayName":
                    member.get("displayName"),
                "userPrincipalName":
                    member.get(
                        "userPrincipalName",
                        "N/A",
                    ),
                "objectType":
                    member.get(
                        "@odata.type",
                        "",
                    ).replace(
                        "#microsoft.graph.",
                        "",
                    ),
            })

        results.append({
            "roleId": role.get("id"),
            "roleName":
                role.get("displayName"),
            "members":
                member_details,
        })

    return results


# ============================================================
# 8. SERVICE PRINCIPAL CERTIFICATES + APP PERMISSIONS
# ============================================================

def check_app_certificates_and_permissions():
    """
    Audits service principals for:

    - Certificates
    - App role assignments
    - Microsoft Graph application permissions

    This helps identify:

        User
        ↓
        Application ownership
        ↓
        Credential control
        ↓
        Privileged application permissions
    """

    headers = _get_headers()

    url = (
        f"{GRAPH_V1}/servicePrincipals"
        "?$select=id,appId,displayName,keyCredentials,passwordCredentials"
    )

    service_principals = _get_all(
        url,
        headers,
    )

    if isinstance(service_principals, dict) and "error" in service_principals:
        return service_principals

    results = []

    for sp in service_principals:

        sp_id = sp.get("id")

        key_credentials = sp.get(
            "keyCredentials",
            [],
        )

        password_credentials = sp.get(
            "passwordCredentials",
            [],
        )

        roles_url = (
            f"{GRAPH_V1}/servicePrincipals/"
            f"{sp_id}/appRoleAssignments"
        )

        app_roles = _get_all(
            roles_url,
            headers,
        )

        if isinstance(app_roles, dict):
            app_roles = []

        role_details = []

        for assignment in app_roles:

            role_details.append({
                "id": assignment.get("id"),
                "principalId":
                    assignment.get(
                        "principalId"
                    ),
                "resourceId":
                    assignment.get(
                        "resourceId"
                    ),
                "appRoleId":
                    assignment.get(
                        "appRoleId"
                    ),
            })

        if (
            key_credentials
            or password_credentials
            or role_details
        ):

            results.append({
                "servicePrincipalId":
                    sp_id,

                "displayName":
                    sp.get("displayName"),

                "appId":
                    sp.get("appId"),

                "hasCertificates":
                    len(key_credentials) > 0,

                "certificateCount":
                    len(key_credentials),

                "hasClientSecrets":
                    len(password_credentials) > 0,

                "clientSecretCount":
                    len(password_credentials),

                "appRoleAssignments":
                    role_details,
            })

    return results


# ============================================================
# 9. GROUP OWNERSHIP / ESCALATION
# ============================================================

def check_group_ownership_escalations():
    """
    Audits groups for ownership relationships.

    Important relationships:

        User
        ↓
        Group owner
        ↓
        Group membership modification
        ↓
        Privileged group membership
        ↓
        Directory role
    """

    headers = _get_headers()

    url = (
        f"{GRAPH_V1}/groups"
        "?$select="
        "id,"
        "displayName,"
        "isAssignableToRole,"
        "securityEnabled,"
        "mailEnabled"
    )

    groups = _get_all(
        url,
        headers,
    )

    if isinstance(groups, dict) and "error" in groups:
        return groups

    findings = []

    for group in groups:

        group_id = group.get("id")

        owners_url = (
            f"{GRAPH_V1}/groups/{group_id}/owners"
            "?$select=id,displayName,userPrincipalName"
        )

        owners = _get_all(
            owners_url,
            headers,
        )

        if isinstance(owners, dict):
            owners = []

        owner_details = []

        for owner in owners:

            owner_details.append({
                "id": owner.get("id"),
                "displayName":
                    owner.get("displayName"),
                "userPrincipalName":
                    owner.get(
                        "userPrincipalName",
                        "N/A",
                    ),
                "objectType":
                    owner.get(
                        "@odata.type",
                        "",
                    ).replace(
                        "#microsoft.graph.",
                        "",
                    ),
            })

        members_url = (
            f"{GRAPH_V1}/groups/{group_id}/members"
            "?$select=id,displayName,userPrincipalName"
        )

        members = _get_all(
            members_url,
            headers,
        )

        if isinstance(members, dict):
            members = []

        member_details = []

        for member in members:

            member_details.append({
                "id": member.get("id"),
                "displayName":
                    member.get(
                        "displayName"
                    ),
                "userPrincipalName":
                    member.get(
                        "userPrincipalName"
                    ),
                "objectType":
                    member.get(
                        "@odata.type",
                        "",
                    ).replace(
                        "#microsoft.graph.",
                        "",
                    ),
            })

        if owner_details:

            findings.append({
                "groupId":
                    group_id,

                "groupName":
                    group.get(
                        "displayName"
                    ),

                "isAssignableToRole":
                    group.get(
                        "isAssignableToRole",
                        False,
                    ),

                "securityEnabled":
                    group.get(
                        "securityEnabled"
                    ),

                "mailEnabled":
                    group.get(
                        "mailEnabled"
                    ),

                "owners":
                    owner_details,

                "members":
                    member_details,

                "memberCount":
                    len(member_details),
            })

    return findings


# ============================================================
# 10. PIM GROUP ELIGIBILITIES
# ============================================================

def get_pim_group_eligibilities():
    """
    Retrieves PIM eligible group assignments.

    Important relationships:

        User
        ↓
        PIM eligible membership
        ↓
        Activate
        ↓
        Group privileges

    OR:

        User
        ↓
        PIM eligible ownership
        ↓
        Activate
        ↓
        Become group owner
        ↓
        Modify membership
    """

    headers = _get_headers()

    url = (
        f"{GRAPH_BETA}/identityGovernance/"
        "privilegedAccess/group/"
        "eligibilitySchedules"
    )

    assignments = _get_all(
        url,
        headers,
    )

    if isinstance(assignments, dict) and "error" in assignments:
        return assignments

    results = []

    for item in assignments:

        principal_id = item.get(
            "principalId"
        )

        group_id = item.get(
            "groupId"
        )

        principal = _get_object_name(
            principal_id,
            headers,
        )

        group = _get_object_name(
            group_id,
            headers,
        )

        results.append({

            "id":
                item.get("id"),

            "principalId":
                principal_id,

            "principal":
                principal,

            "groupId":
                group_id,

            "group":
                group,

            "accessId":
                item.get("accessId"),

            "status":
                item.get("status"),

            "scheduleInfo":
                item.get("scheduleInfo"),
        })

    return results


# ============================================================
# 11. ADMINISTRATIVE UNITS
# ============================================================

def get_administrative_units():
    """
    Retrieves Administrative Units.

    Particularly important for identifying:

        User attribute
        ↓
        Dynamic AU membership
        ↓
        AU-scoped role
        ↓
        Privilege escalation
    """

    headers = _get_headers()

    url = (
        f"{GRAPH_V1}/directory/administrativeUnits"
        "?$select="
        "id,"
        "displayName,"
        "membershipType,"
        "membershipRule,"
        "membershipRuleProcessingState"
    )

    units = _get_all(
        url,
        headers,
    )

    if isinstance(units, dict) and "error" in units:
        return units

    results = []

    for au in units:

        au_id = au.get(
            "id"
        )

        members_url = (
            f"{GRAPH_V1}/directory/"
            f"administrativeUnits/"
            f"{au_id}/members"
            "?$select=id,displayName,userPrincipalName"
        )

        members = _get_all(
            members_url,
            headers,
        )

        if isinstance(members, dict):
            members = []

        member_details = []

        for member in members:

            member_details.append({
                "id":
                    member.get("id"),

                "displayName":
                    member.get(
                        "displayName"
                    ),

                "userPrincipalName":
                    member.get(
                        "userPrincipalName"
                    ),

                "objectType":
                    member.get(
                        "@odata.type",
                        "",
                    ).replace(
                        "#microsoft.graph.",
                        "",
                    ),
            })

        results.append({

            "id":
                au_id,

            "displayName":
                au.get(
                    "displayName"
                ),

            "membershipType":
                au.get(
                    "membershipType"
                ),

            "membershipRule":
                au.get(
                    "membershipRule"
                ),

            "membershipRuleProcessingState":
                au.get(
                    "membershipRuleProcessingState"
                ),

            "isDynamic":
                au.get(
                    "membershipType"
                ) == "Dynamic",

            "members":
                member_details,

            "memberCount":
                len(member_details),
        })

    return results


# ============================================================
# 12. DETAILED ROLE ASSIGNMENTS
# ============================================================

def get_role_assignments_detailed():
    """
    Retrieves detailed Entra directory role assignments.

    Resolves:

        Principal
        Role
        Scope
        Role permissions

    Particularly useful for:

        Group
        ↓
        Directory role
        ↓
        Administrative Unit scope
    """

    headers = _get_headers()

    url = (
        f"{GRAPH_V1}/roleManagement/"
        "directory/roleAssignments"
    )

    assignments = _get_all(
        url,
        headers,
    )

    if isinstance(assignments, dict) and "error" in assignments:
        return assignments

    results = []

    for assignment in assignments:

        principal_id = assignment.get(
            "principalId"
        )

        role_id = assignment.get(
            "roleDefinitionId"
        )

        scope_id = assignment.get(
            "directoryScopeId"
        )

        # ----------------------------------------------------
        # Resolve principal
        # ----------------------------------------------------

        principal = _get_object_name(
            principal_id,
            headers,
        )

        # ----------------------------------------------------
        # Resolve role definition
        # ----------------------------------------------------

        role_url = (
            f"{GRAPH_V1}/roleManagement/"
            f"directory/roleDefinitions/"
            f"{role_id}"
        )

        role_response = requests.get(
            role_url,
            headers=headers,
            timeout=30,
        )

        role_name = "Unknown"

        permissions = []

        if role_response.status_code == 200:

            role = role_response.json()

            role_name = role.get(
                "displayName",
                "Unknown",
            )

            for permission in role.get(
                "rolePermissions",
                [],
            ):

                permissions.extend(
                    permission.get(
                        "allowedResourceActions",
                        [],
                    )
                )

        # ----------------------------------------------------
        # Determine scope type
        # ----------------------------------------------------

        scope_type = "Tenant"

        scope_object_id = None

        if scope_id and scope_id != "/":

            if scope_id.startswith(
                "/administrativeUnits/"
            ):

                scope_type = "AdministrativeUnit"

                scope_object_id = (
                    scope_id.replace(
                        "/administrativeUnits/",
                        "",
                    )
                )

            elif scope_id.startswith(
                "/groups/"
            ):

                scope_type = "Group"

                scope_object_id = (
                    scope_id.replace(
                        "/groups/",
                        "",
                    )
                )

            else:

                scope_type = "Other"

        # ----------------------------------------------------
        # Resolve AU name if applicable
        # ----------------------------------------------------

        scope_object = None

        if scope_type == "AdministrativeUnit":

            au_url = (
                f"{GRAPH_V1}/directory/"
                f"administrativeUnits/"
                f"{scope_object_id}"
                "?$select=id,displayName,"
                "membershipType,membershipRule"
            )

            au_response = requests.get(
                au_url,
                headers=headers,
                timeout=30,
            )

            if au_response.status_code == 200:

                au = au_response.json()

                scope_object = {
                    "id":
                        au.get("id"),

                    "displayName":
                        au.get(
                            "displayName"
                        ),

                    "membershipType":
                        au.get(
                            "membershipType"
                        ),

                    "membershipRule":
                        au.get(
                            "membershipRule"
                        ),
                }

        # ----------------------------------------------------
        # Build result
        # ----------------------------------------------------

        results.append({

            "assignmentId":
                assignment.get("id"),

            "principalId":
                principal_id,

            "principal":
                principal,

            "roleDefinitionId":
                role_id,

            "roleName":
                role_name,

            "directoryScopeId":
                scope_id,

            "scopeType":
                scope_type,

            "scopeObject":
                scope_object,

            "permissions":
                permissions,
        })

    return results


# ============================================================
# 13. OPTIONAL: BUILD A HIGH-LEVEL SECURITY GRAPH
# ============================================================

def build_security_relationships():
    """
    Collects the major Entra relationships into one structure.

    This is useful when you want the LLM to perform correlation
    without having to independently request every data source.
    """

    return {

        "users":
            get_tenant_users(),

        "directoryRoles":
            get_directory_roles_and_members(),

        "pimGroupEligibilities":
            get_pim_group_eligibilities(),

        "administrativeUnits":
            get_administrative_units(),

        "roleAssignments":
            get_role_assignments_detailed(),

        "groupOwnership":
            check_group_ownership_escalations(),

        "servicePrincipals":
            get_service_principals_and_owners(),

        "applicationPermissions":
            check_app_certificates_and_permissions(),

        "conditionalAccess":
            get_conditional_access_policies(),
    }
