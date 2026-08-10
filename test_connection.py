import os
import requests
from dotenv import load_dotenv
from msal import ConfidentialClientApplication

# Load credentials from .env
load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# Initialize MSAL Confidential Client
app = ConfidentialClientApplication(
    CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=f"https://login.microsoftonline.com/{TENANT_ID}"
)

print("🔑 Authenticating with Entra ID...")
result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

if "access_token" in result:
    print("✅ Authenticated successfully!\n")
    headers = {"Authorization": f"Bearer {result['access_token']}"}
    
    # Test 1: Fetch Users
    print("📋 Querying Users from Microsoft Graph...")
    res = requests.get("https://graph.microsoft.com/v1.0/users", headers=headers)
    if res.status_code == 200:
        users = res.json().get("value", [])
        print(f"Found {len(users)} users in tenant:")
        for user in users[:5]:
            print(f"  • {user.get('displayName')} ({user.get('userPrincipalName')})")
    else:
        print(f"❌ Failed to fetch users: {res.status_code} - {res.text}")

else:
    print(f"❌ Authentication failed: {result.get('error_description')}")
