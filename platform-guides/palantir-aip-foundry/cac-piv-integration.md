# Palantir Foundry CAC/PIV Integration Guide

## Overview

Getting into Palantir Foundry the first time is where most practitioners run into trouble. The platform is sophisticated enough that the authentication layer — which sits in front of everything — gets treated as an afterthought. It isn't. On a DoD program, CAC/PIV-based access to Foundry is the gateway to the Ontology, the datasets, the Code Workspaces, and the AIP functionality that makes the platform worth deploying. If you can't get in, none of the rest matters.

This guide covers three things: how Foundry's authentication architecture works in federal deployments, the specific integration patterns for CAC and PIV certificates, and the token management workflows that practitioners who write automation code need to understand. The Databricks guide in this handbook covers similar ground for that platform. Foundry's model is different in ways that matter.

Foundry received FedRAMP High authorization in December 2024 for the full Palantir Federal Cloud Service (PFCS) product suite. IL4 and IL5 access runs on Microsoft Azure Government and Azure Government Secret. IL6 access runs on Azure Government Top Secret via the Palantir/Microsoft partnership announced in August 2024. Each impact level has a distinct authentication configuration. This guide addresses the most common federal deployment: FedRAMP High and IL4/IL5 on Azure Government.

---

## Prerequisites

### System Requirements

- CAC card with valid DoD PKI authentication certificate (not expired, not revoked)
- CAC card reader installed and recognized by the operating system
- OpenSC PKCS#11 library installed (Windows, Linux, or macOS)
- Browser with CAC certificate support (recommended: Chrome with the Smart Card middleware configured, or Firefox with manual PKCS#11 module registration)
- Network access to your Foundry enrollment URL

### Foundry-Specific Requirements

- Foundry enrollment URL from your program's IT office (format: `https://yourstack.palantirfoundry.com`)
- User account provisioned in Foundry — account creation does NOT happen automatically on first login; a Foundry administrator must create your account before certificate authentication will work
- Role assignment in Foundry — being provisioned an account with no roles gives you access to nothing useful; confirm your role assignments with your Foundry admin before spending time debugging authentication
- Your DoD CAC must be enrolled in the DoD PKI infrastructure (standard for all DoD personnel and most contractors supporting cleared programs)

### Software Dependencies

```bash
# For local development with foundry-dev-tools
pip install foundry-dev-tools

# For CAC certificate inspection and PKCS#11 operations
pip install PyKCS11 cryptography

# For programmatic API access
pip install requests
```

---

## Architecture Overview

Foundry's authentication in federal deployments uses a layered model:

```
[CAC Card]
    |
    | PKCS#11 interface
    v
[Browser CAC Middleware]
    |
    | Client certificate presented during TLS handshake
    v
[Foundry Authentication Gateway]
    |
    | Certificate validation against DoD PKI
    v
[DoD PKI OCSP / CRL Check]
    |
    | Certificate verified, EDIPI extracted from Subject CN
    v
[Foundry Identity Resolution]
    |
    | EDIPI matched to provisioned Foundry account
    v
[Foundry Session Token Issued]
    |
    | Bearer token scoped to user's roles and permissions
    v
[Foundry Platform Access]
    |-- Code Workspaces (JupyterLab, RStudio)
    |-- Data Catalog / Ontology
    |-- Workshop Applications
    |-- AIP Logic and Agent Studio
    |-- Pipeline Builder
```

The critical point in this architecture is the EDIPI-to-account mapping step. Foundry does not provision accounts on demand. If your EDIPI is not mapped to a Foundry user account, the authentication will fail silently from your perspective — the platform simply refuses to create a session. Contact your Foundry administrator and ask specifically: "Is my EDIPI mapped to a provisioned account, and what roles have been assigned?"

---

## Quick Start

### 1. Interactive Browser Login (Standard Workflow)

This is how most users access Foundry day-to-day. No code required.

**Step 1: Insert your CAC card** into the reader before opening the browser. Order matters on Windows systems — inserting the card after the browser session has started sometimes causes the middleware to miss the certificate.

**Step 2: Navigate to your Foundry URL.** Your program's IT office provides this. It looks like `https://yourstack.palantirfoundry.com`. Do not try the commercial Palantir documentation URLs — they will not work for a government enrollment.

**Step 3: Select certificate when prompted.** The browser will display a certificate selection dialog. Select the certificate labeled "Authentication" or "AUTH" — not "Email Signature" or "Encryption." DoD CAC cards contain three certificates; selecting the wrong one is a common mistake.

**Step 4: Enter your CAC PIN.** The PIN is the same one you use for Windows login.

**Step 5: Foundry loads.** If you see an error instead, the most common causes are:
- Account not provisioned (contact your Foundry admin)
- Certificate revoked (contact your PKI/CAC administrator)
- Wrong certificate selected (retry with the authentication certificate)
- Network policy blocking the Foundry URL (contact IT to add the enrollment URL to the proxy allowlist)

---

### 2. Basic Python Configuration

Once you have browser access, you can configure programmatic access for notebooks and scripts.

```python
from security_compliance.auth.platform_adapters import PlatformConfig
from security_compliance.auth.platform_adapters import FoundryAuthAdapter

# Configure Foundry connection
# Get your enrollment URL from your program's IT office
# Never hardcode the token — use environment variables
config = PlatformConfig(
    platform_name="palantir_foundry",
    base_url="https://yourstack.palantirfoundry.com",
    api_version="v1",
    authentication_endpoint="/multipass/api/v1/authenticate",
    token_endpoint="/multipass/api/v1/token",
    user_info_endpoint="/api/v1/userinfo",
    timeout=30,
    max_retries=3,
    verify_ssl=True,
    additional_config={
        "enrollment_name": "your-enrollment",
        "auth_method": "certificate",
        "il_level": "IL4",
        "azure_tenant_id": "your-azure-tenant-id"
    }
)

# Initialize adapter
adapter = FoundryAuthAdapter(config)
```

---

### 3. Authentication Flow

```python
from security_compliance.auth.cac_piv_integration import CACAuthenticationManager
from security_compliance.auth.platform_adapters import AuthenticationStatus
from cryptography.hazmat.primitives import serialization

# Initialize authentication manager
auth_manager = CACAuthenticationManager()

# Authenticate user with CAC PIN (in production, get PIN from secure input)
# Never hardcode or log the PIN
credentials = auth_manager.authenticate_user("user_pin")

if credentials:
    print(f"CAC authentication successful for EDIPI: {credentials.edipi}")

    # Get certificate data for Foundry challenge-response
    certificate_data = credentials.certificate.public_bytes(serialization.Encoding.DER)

    # Generate challenge and sign
    challenge = adapter._generate_challenge()
    signature = auth_manager.authenticator.sign_data(challenge)

    # Authenticate with Foundry
    result = adapter.authenticate_with_cac(
        certificate_data=certificate_data,
        signature=signature,
        challenge=challenge,
        additional_params={
            "enrollment_name": "your-enrollment",
            "il_level": "IL4"
        }
    )

    if result.status == AuthenticationStatus.SUCCESS:
        print(f"Foundry authentication successful")
        print(f"Session token issued (expires in session_timeout minutes)")

        # Retrieve user information
        user_info = adapter.get_user_info(result.session_token)
        print(f"Username: {user_info.get('username')}")
        print(f"Groups: {user_info.get('groups', [])}")

    else:
        print(f"Authentication failed: {result.error_message}")
        print(
            "Verify: (1) account provisioned in Foundry, "
            "(2) roles assigned, (3) certificate not revoked"
        )
```

---

## IL4/IL5 Access Configuration

The impact level of your Foundry deployment determines which network you access it from and what additional authentication controls apply.

### IL4 Access (FedRAMP High / Azure Government)

IL4 is the standard configuration for sensitive but unclassified DoD data. Access is from NIPRNet or approved VPN.

```python
# IL4 configuration — FedRAMP High on Azure Government
il4_config = PlatformConfig(
    platform_name="palantir_foundry",
    base_url="https://yourstack.palantirfoundry.com",
    verify_ssl=True,
    additional_config={
        "il_level": "IL4",
        "network": "NIPRNet",
        "azure_region": "usgovarizona",   # or usgovvirginia
        "authentication_provider": "dod_pki",
        "session_timeout_minutes": 480,   # 8 hours — standard IL4 policy
        "require_cac": True,
        "allow_software_certificates": False  # hardware CAC required at IL4+
    }
)
```

### IL5 Access (Azure Government Secret)

IL5 covers controlled unclassified information with higher sensitivity. Access is from NIPRNet with additional controls; some programs route IL5 through SIPRNet.

```python
# IL5 configuration — Azure Government Secret
il5_config = PlatformConfig(
    platform_name="palantir_foundry",
    base_url="https://yourstack-il5.palantirfoundry.com",  # different URL for IL5
    verify_ssl=True,
    additional_config={
        "il_level": "IL5",
        "network": "NIPRNet_or_SIPRNet",
        "azure_region": "usdodcentral",   # DoD-specific Azure regions for IL5+
        "authentication_provider": "dod_pki",
        "session_timeout_minutes": 240,   # 4 hours — tighter IL5 policy
        "require_cac": True,
        "allow_software_certificates": False,
        "require_mfa": True               # additional MFA factor at IL5
    }
)
```

### Checking Your IL Level

If you are unsure which IL level your Foundry deployment supports, look at the URL your program office gave you. IL4 and IL5 deployments have different URLs and different certificate requirements. Never attempt to access an IL5 system from a network or machine that has not been approved for that level.

```python
def get_enrollment_il_level(adapter) -> str:
    """
    Query the Foundry enrollment info endpoint to determine IL level.
    This is read from the Foundry environment, not configured manually.
    """
    import requests

    try:
        response = requests.get(
            f"{adapter.config.base_url}/api/v1/enrollment-info",
            timeout=15,
            verify=True
        )
        if response.status_code == 200:
            info = response.json()
            il_level = info.get("impactLevel", "UNKNOWN")
            print(f"Enrollment: {info.get('enrollmentName', 'unknown')}")
            print(f"Impact Level: {il_level}")
            print(f"Classification: {info.get('classificationLevel', 'UNCLASSIFIED')}")
            return il_level
    except Exception as e:
        print(f"Could not retrieve enrollment info: {e}")

    return "UNKNOWN"
```

---

## Certificate-Based Authentication

### Certificate Validation

Foundry validates CAC certificates against the DoD PKI certificate chain. Understanding what gets checked helps you diagnose authentication failures.

```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtendedKeyUsageOID
import datetime

def validate_cac_certificate_for_foundry(cert_der_bytes: bytes) -> dict:
    """
    Validate that a CAC certificate meets Foundry's requirements for
    certificate-based authentication.

    Foundry requires:
    1. Certificate is from a trusted DoD CA (DoD Root CA 3 or 4)
    2. Certificate has Client Authentication extended key usage
    3. Certificate is not expired
    4. Certificate has a valid EDIPI in the Subject CN
    5. Certificate is not revoked (checked via OCSP by Foundry server)

    This function checks items 1-4 client-side, before sending to Foundry.
    Revocation (item 5) is always checked server-side.
    """
    cert = x509.load_der_x509_certificate(cert_der_bytes, default_backend())
    now = datetime.datetime.now(datetime.timezone.utc)
    result = {
        "valid": True,
        "issues": [],
        "cert_subject": None,
        "cert_issuer": None,
        "expiry": None,
        "edipi": None,
        "has_client_auth_eku": False,
        "is_expired": False,
        "days_until_expiry": None
    }

    # Subject and issuer
    result["cert_subject"] = cert.subject.rfc4514_string()
    result["cert_issuer"] = cert.issuer.rfc4514_string()

    # Expiry check
    result["expiry"] = cert.not_valid_after_utc.isoformat()
    delta = cert.not_valid_after_utc - now
    result["days_until_expiry"] = delta.days
    result["is_expired"] = delta.days < 0

    if result["is_expired"]:
        result["valid"] = False
        result["issues"].append(
            f"Certificate expired {abs(delta.days)} days ago. "
            "Contact your CAC administrator for a renewal."
        )
    elif delta.days < 30:
        result["issues"].append(
            f"Certificate expires in {delta.days} days. "
            "Schedule CAC renewal before expiration."
        )

    # Check for Client Authentication EKU
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        result["has_client_auth_eku"] = (
            ExtendedKeyUsageOID.CLIENT_AUTH in eku.value
        )
        if not result["has_client_auth_eku"]:
            result["valid"] = False
            result["issues"].append(
                "Certificate does not have Client Authentication EKU. "
                "Select the 'Authentication' certificate, not 'Email Signature'."
            )
    except x509.ExtensionNotFound:
        result["valid"] = False
        result["issues"].append("Certificate missing Extended Key Usage extension.")

    # Extract EDIPI from Subject CN
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if cn_attrs:
        cn = cn_attrs[0].value
        parts = cn.split(".")
        for part in reversed(parts):
            if part.isdigit() and len(part) == 10:
                result["edipi"] = part
                break
        if not result["edipi"]:
            result["valid"] = False
            result["issues"].append(
                f"No 10-digit EDIPI found in Subject CN: {cn}. "
                "Verify this is a DoD CAC certificate."
            )

    return result


def check_dod_ca_chain(cert_der_bytes: bytes) -> bool:
    """
    Verify certificate is issued by a trusted DoD Certificate Authority.

    DoD Root CAs currently in use:
    - DoD Root CA 3 (SHA-256)
    - DoD Root CA 4 (SHA-256)
    - DoD Root CA 5 (SHA-256, newer cards)

    This check confirms the issuer's CN matches expected DoD CA names.
    Full chain validation (including revocation) happens on the Foundry server.
    """
    cert = x509.load_der_x509_certificate(cert_der_bytes, default_backend())
    issuer_cns = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)

    trusted_ca_names = [
        "DoD Root CA 3",
        "DoD Root CA 4",
        "DoD Root CA 5",
        "DOD ID CA-59",
        "DOD ID CA-62",
        "DOD ID CA-65",
        "DOD ID CA-66",
        "DOD ID CA-70",
    ]

    if issuer_cns:
        issuer_cn = issuer_cns[0].value
        for trusted_name in trusted_ca_names:
            if trusted_name.lower() in issuer_cn.lower():
                return True

    return False
```

---

## Foundry Token Management

### Token Architecture

Once CAC authentication succeeds, Foundry issues a session token. Understanding how these tokens work determines how you build reliable automated workflows on Foundry.

Foundry uses the Multipass authentication service. A successful CAC login produces:
- A **session token** for browser-based access — scoped to the current session, invalidated on logout
- A **bearer token** for API access — the same token your scripts use

In Code Workspaces (JupyterLab), the bearer token is injected into the workspace environment automatically. You do not manage it directly. In local development with foundry-dev-tools, the tool handles token refresh transparently.

For programmatic API access from outside a Code Workspace, you need a **long-lived token** issued through the Foundry administrative token management interface.

```python
import os
import requests
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any

class FoundryTokenLifecycle:
    """
    Manages the lifecycle of Foundry bearer tokens for programmatic access.

    In Code Workspaces: Use the auto-injected token — do not instantiate this class.
    In local dev: Use foundry-dev-tools instead — it handles this automatically.
    For production jobs: Use this class with a token issued by your Foundry admin.

    Never store tokens in code. Use environment variables or
    Foundry's built-in secret management.
    """

    def __init__(self, host: Optional[str] = None, token: Optional[str] = None):
        self.host = host or os.environ.get("FOUNDRY_HOST")
        self.token = token or os.environ.get("FOUNDRY_TOKEN")

    def validate_token(self) -> Dict[str, Any]:
        """
        Validate the current token and retrieve user context.

        Returns a dict with:
            valid: bool
            username: str or None
            groups: list
            error: str or None
        """
        if not self.host or not self.token:
            return {
                "valid": False,
                "username": None,
                "groups": [],
                "error": "FOUNDRY_HOST or FOUNDRY_TOKEN not set"
            }

        try:
            response = requests.get(
                f"{self.host}/api/v1/userinfo",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=15
            )

            if response.status_code == 200:
                user = response.json()
                return {
                    "valid": True,
                    "username": user.get("username"),
                    "groups": user.get("groups", []),
                    "error": None
                }
            elif response.status_code == 401:
                return {
                    "valid": False,
                    "username": None,
                    "groups": [],
                    "error": (
                        "Token invalid or expired. "
                        "Re-authenticate via browser or run: foundry-dev-tools login"
                    )
                }
            else:
                return {
                    "valid": False,
                    "username": None,
                    "groups": [],
                    "error": f"Unexpected response: HTTP {response.status_code}"
                }

        except requests.RequestException as e:
            return {
                "valid": False,
                "username": None,
                "groups": [],
                "error": f"Connection error: {e}"
            }

    def access_dataset(
        self,
        dataset_rid: str,
        branch: str = "master"
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve dataset metadata using the current token.

        dataset_rid: The Resource Identifier of the dataset.
                     Format: ri.foundry.main.dataset.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
                     Find RIDs in the Foundry Data Catalog under dataset settings.

        This is the first API call to make when setting up a new data pipeline —
        verify the dataset is accessible before writing any processing code.
        """
        if not self.token or not self.host:
            print("Token not configured. Set FOUNDRY_HOST and FOUNDRY_TOKEN.")
            return None

        response = requests.get(
            f"{self.host}/api/v1/datasets/{dataset_rid}",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=15
        )

        if response.status_code == 200:
            dataset = response.json()
            print(f"Dataset accessible: {dataset.get('name', dataset_rid)}")
            print(f"  RID: {dataset_rid}")
            print(f"  Branch: {branch}")
            print(f"  Created: {dataset.get('created', {}).get('time', 'unknown')}")
            return dataset
        elif response.status_code == 403:
            print(
                f"Access denied to dataset {dataset_rid}. "
                "Your Foundry role does not include permission for this dataset. "
                "Contact the dataset owner or your Foundry admin."
            )
            return None
        elif response.status_code == 404:
            print(
                f"Dataset {dataset_rid} not found. "
                "Verify the RID is correct. RIDs are case-sensitive."
            )
            return None
        else:
            print(f"Unexpected response: HTTP {response.status_code}")
            return None
```

---

## Advanced Configuration

### SAML and OIDC Federation

Some Foundry government deployments integrate with external identity providers via SAML 2.0 or OIDC, with the CAC certificate used as the primary assertion to the IdP rather than directly to Foundry. In this pattern:

1. The user presents the CAC certificate to the agency's IdP (typically Microsoft ADFS or Azure AD with certificate-based auth configured)
2. The IdP validates the certificate against the DoD PKI and issues a SAML assertion or OIDC token
3. The SAML/OIDC token is presented to Foundry for session establishment

This is the common pattern in large DoD deployments where multiple applications share a single sign-on infrastructure.

```python
def configure_saml_federation(adapter, saml_config: dict):
    """
    Configure Foundry adapter for SAML-federated CAC authentication.

    saml_config fields:
        idp_metadata_url: URL of the IdP's SAML metadata endpoint
        sp_entity_id:     Foundry's Service Provider entity ID (from your Foundry admin)
        assertion_consumer_service_url: ACS URL for Foundry (from your Foundry admin)
        sign_assertions:  bool — whether assertions should be signed (required at IL4+)
    """
    # SAML federation configuration is managed by your Foundry administrator
    # and your agency's IdP team. This function captures the configuration
    # parameters that the adapter needs to initiate SAML-federated auth flows.

    federation_config = {
        "auth_method": "saml_federation",
        "idp_metadata_url": saml_config.get("idp_metadata_url"),
        "sp_entity_id": saml_config.get("sp_entity_id"),
        "acs_url": saml_config.get("assertion_consumer_service_url"),
        "sign_assertions": saml_config.get("sign_assertions", True),
        "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "attribute_mapping": {
            "edipi": "urn:oid:2.16.840.1.101.2.1.21.1",  # DoD EDIPI OID
            "email": "urn:oid:1.2.840.113549.1.9.1",
            "given_name": "urn:oid:2.5.4.42",
            "surname": "urn:oid:2.5.4.4"
        }
    }

    adapter.config.additional_config.update(federation_config)
    return adapter


def configure_azure_ad_certificate_auth(adapter, azure_config: dict):
    """
    Configure Foundry for Azure AD certificate-based authentication (CBA).

    This is the pattern for Foundry deployments on Azure Government where
    Azure AD has been configured to accept DoD CAC certificates directly.

    Palantir's FedRAMP High deployment on Azure Government supports this pattern.

    azure_config fields:
        tenant_id:       Azure AD tenant ID (from your IT office)
        client_id:       Foundry's application registration client ID
        authority:       Azure Government authority URL
    """
    azure_auth_config = {
        "auth_method": "azure_ad_cba",
        "tenant_id": azure_config.get("tenant_id"),
        "client_id": azure_config.get("client_id"),
        "authority": azure_config.get(
            "authority",
            "https://login.microsoftonline.us"  # Azure Government endpoint
        ),
        "certificate_based_auth": True,
        "require_mfa": True,
        "token_endpoint": f"https://login.microsoftonline.us/{azure_config.get('tenant_id')}/oauth2/v2.0/token",
        "scope": [f"api://{azure_config.get('client_id')}/.default"]
    }

    adapter.config.additional_config.update(azure_auth_config)
    return adapter
```

### Multipass Token Configuration

Foundry's internal authentication service (Multipass) issues tokens with configurable scopes. Understanding token scopes prevents the "why can I log in but can't access this dataset" problem.

```python
def request_scoped_token(
    adapter,
    session_token: str,
    required_scopes: list
) -> Optional[str]:
    """
    Request a token scoped to specific Foundry capabilities.

    Foundry token scopes determine what API endpoints the token can access.
    Standard scopes for data science workflows:
        - "api:read-data"         — read datasets and their schemas
        - "api:write-data"        — write to datasets (transforms output)
        - "api:execute-code"      — execute code in Code Workspaces
        - "compass:read"          — read from the Compass file browser
        - "ontology:read"         — read Ontology objects and properties
        - "models:read"           — access model registry
        - "models:write"          — publish models

    At IL4/IL5, scope requests are audited and may require additional approval
    for sensitive scopes like write access to production datasets.
    """
    import requests

    token_request = {
        "token": session_token,
        "scopes": required_scopes,
        "description": "Data science workflow token — automated pipeline access"
    }

    try:
        response = requests.post(
            f"{adapter.config.base_url}/multipass/api/v1/token",
            headers={
                "Authorization": f"Bearer {session_token}",
                "Content-Type": "application/json"
            },
            json=token_request,
            timeout=30
        )

        if response.status_code == 200:
            scoped_token = response.json().get("bearerToken")
            print(f"Scoped token issued for: {required_scopes}")
            return scoped_token
        elif response.status_code == 403:
            print(
                "Scope request denied. Your Foundry role may not include "
                f"permission for the requested scopes: {required_scopes}. "
                "Contact your Foundry administrator."
            )
            return None
        else:
            print(f"Token request failed: HTTP {response.status_code}")
            return None

    except requests.RequestException as e:
        print(f"Token request error: {e}")
        return None
```

---

## Security and Compliance

### Audit Logging

All authentication events and dataset access operations are automatically logged in Foundry's audit system. For DoD programs, this is a compliance requirement under both the FedRAMP High authorization and any program-specific ATO.

```python
import requests
from datetime import datetime, timezone, timedelta

def retrieve_auth_audit_log(
    adapter,
    session_token: str,
    hours_back: int = 24
) -> list:
    """
    Retrieve recent authentication audit events for compliance review.

    Foundry logs every login, logout, token issuance, and authentication
    failure to its internal audit system. Compliance officers reviewing
    the ATO boundary can pull these records via the audit API.

    This function requires audit API permissions — typically restricted to
    Foundry administrators and designated compliance personnel.

    Returns list of audit events, or empty list if access is denied.
    """
    since = (
        datetime.now(tz=timezone.utc) - timedelta(hours=hours_back)
    ).isoformat()

    try:
        response = requests.get(
            f"{adapter.config.base_url}/api/v1/audit/authentication",
            headers={"Authorization": f"Bearer {session_token}"},
            params={
                "startTime": since,
                "eventType": "AUTHENTICATION",
                "limit": 100
            },
            timeout=30
        )

        if response.status_code == 200:
            events = response.json().get("events", [])
            print(f"Retrieved {len(events)} authentication events from the last {hours_back}h")
            return events
        elif response.status_code == 403:
            print(
                "Audit API access denied. "
                "Audit log retrieval requires elevated Foundry permissions."
            )
            return []
        else:
            print(f"Audit API response: HTTP {response.status_code}")
            return []

    except requests.RequestException as e:
        print(f"Audit API error: {e}")
        return []


def log_programmatic_access_event(
    event_type: str,
    user_edipi: str,
    resource_rid: str,
    il_level: str,
    success: bool
) -> None:
    """
    Log programmatic access events to your program's external audit system.

    Foundry logs platform-level events internally, but DoD programs with
    independent audit requirements may need to send access events to a
    program-specific SIEM or audit log service.

    This function sends a standardized event record. Integrate with your
    program's audit infrastructure by modifying the send_to_audit_service
    call at the end.
    """
    event = {
        "event_type": event_type,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "platform": "palantir_foundry",
        "il_level": il_level,
        "user_edipi": user_edipi,
        "resource_rid": resource_rid,
        "success": success,
        "source": "programmatic_api"
    }

    # Replace this with your program's audit service endpoint
    # Do not log tokens or PINs — only identifiers and event metadata
    print(f"Audit event: {event_type} | EDIPI: {user_edipi} | "
          f"Resource: {resource_rid} | Success: {success}")


def setup_session_controls(
    adapter,
    classification_level: str = "UNCLASSIFIED"
) -> dict:
    """
    Configure session controls appropriate for the classification level.

    DoD IL4 and IL5 programs have specific session timeout requirements:
    - IL4: 8-hour session timeout, 30-minute inactivity timeout
    - IL5: 4-hour session timeout, 15-minute inactivity timeout
    - IL6: 2-hour session timeout, 10-minute inactivity timeout

    These are enforced by the Foundry platform but should be reflected
    in your application's session management logic as well.
    """
    session_configs = {
        "UNCLASSIFIED": {
            "session_timeout_minutes": 480,
            "inactivity_timeout_minutes": 30,
            "max_concurrent_sessions": 3,
            "require_session_refresh": False
        },
        "CUI": {
            "session_timeout_minutes": 480,
            "inactivity_timeout_minutes": 30,
            "max_concurrent_sessions": 2,
            "require_session_refresh": True
        },
        "IL4": {
            "session_timeout_minutes": 480,
            "inactivity_timeout_minutes": 30,
            "max_concurrent_sessions": 1,
            "require_session_refresh": True
        },
        "IL5": {
            "session_timeout_minutes": 240,
            "inactivity_timeout_minutes": 15,
            "max_concurrent_sessions": 1,
            "require_session_refresh": True
        }
    }

    config = session_configs.get(
        classification_level, session_configs["UNCLASSIFIED"]
    )

    print(f"Session controls for {classification_level}:")
    print(f"  Session timeout: {config['session_timeout_minutes']} minutes")
    print(f"  Inactivity timeout: {config['inactivity_timeout_minutes']} minutes")
    print(f"  Max concurrent sessions: {config['max_concurrent_sessions']}")

    return config
```

---

## Testing and Validation

### Integration Tests

```python
import unittest
from unittest.mock import Mock, patch, MagicMock

class TestFoundryCACIntegration(unittest.TestCase):
    """
    Integration tests for Foundry CAC authentication.

    These tests mock the network layer to verify authentication logic
    without requiring an actual Foundry instance or CAC card.

    For end-to-end tests against a real Foundry instance, use a
    test enrollment with dedicated test service accounts.
    """

    def setUp(self):
        self.config = PlatformConfig(
            platform_name="palantir_foundry",
            base_url="https://test-foundry.palantirfoundry.com",
            verify_ssl=False,
            additional_config={"il_level": "IL4"}
        )
        self.adapter = FoundryAuthAdapter(self.config)
        self.token_manager = FoundryTokenLifecycle(
            host="https://test-foundry.palantirfoundry.com",
            token="test_bearer_token"
        )

    @patch("requests.get")
    def test_token_validation_success(self, mock_get):
        """Test successful token validation against userinfo endpoint."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "username": "doe.john.a.1234567890",
            "groups": ["data-scientists", "navy-jupiter-users"]
        }
        mock_get.return_value = mock_response

        result = self.token_manager.validate_token()

        self.assertTrue(result["valid"])
        self.assertEqual(result["username"], "doe.john.a.1234567890")
        self.assertEqual(len(result["groups"]), 2)
        self.assertIsNone(result["error"])

    @patch("requests.get")
    def test_token_validation_expired(self, mock_get):
        """Test handling of expired token (HTTP 401)."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        result = self.token_manager.validate_token()

        self.assertFalse(result["valid"])
        self.assertIn("expired", result["error"].lower())

    @patch("requests.get")
    def test_dataset_access_denied(self, mock_get):
        """Test handling of dataset permission denial (HTTP 403)."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response

        result = self.token_manager.access_dataset(
            "ri.foundry.main.dataset.test-rid"
        )

        self.assertIsNone(result)

    def test_certificate_validation_no_client_auth_eku(self):
        """
        Test that non-authentication certificates are rejected.
        A DoD email certificate should fail the EKU check.
        """
        # This test requires a test certificate fixture
        # In a real test suite, use test certificates generated with
        # the correct/incorrect EKU values for positive/negative tests
        pass

    def test_il4_session_controls(self):
        """Test that IL4 session controls use the correct timeout values."""
        controls = setup_session_controls("IL4")

        self.assertEqual(controls["session_timeout_minutes"], 480)
        self.assertEqual(controls["inactivity_timeout_minutes"], 30)
        self.assertTrue(controls["require_session_refresh"])

    def test_il5_session_controls_stricter(self):
        """Test that IL5 session controls are stricter than IL4."""
        il4_controls = setup_session_controls("IL4")
        il5_controls = setup_session_controls("IL5")

        self.assertLess(
            il5_controls["session_timeout_minutes"],
            il4_controls["session_timeout_minutes"]
        )
        self.assertLess(
            il5_controls["inactivity_timeout_minutes"],
            il4_controls["inactivity_timeout_minutes"]
        )
```

---

## Troubleshooting

### Common Issues

**1. Browser shows generic error after certificate selection**

The most common cause is an account provisioning gap. Your certificate authenticated successfully, but there is no Foundry user account mapped to your EDIPI.

```
Diagnosis: Contact your Foundry administrator and ask:
  "Is EDIPI [your 10-digit EDIPI] provisioned in Foundry?"

Your EDIPI is the 10-digit number on the back of your CAC card,
or extractable from your certificate:
```
```python
cert_bytes = read_cac_certificate()
edipi = extract_edipi_from_certificate(cert_bytes)
print(f"Your EDIPI: {edipi}")
```

**2. Certificate selection dialog shows no certificates**

The browser cannot see the CAC card. Common causes:
```
- CAC card not fully inserted
- Card reader driver not installed (check Device Manager on Windows)
- OpenSC middleware not configured for the browser
- CAC inserted AFTER browser was opened (close and reopen browser)
```

**3. Token works in browser but expires immediately in script**

The browser session token and the API bearer token have different lifetimes. Scripts must use a properly issued API token, not the session token from the browser.
```python
# Wrong: using a session token that's tied to the browser session
token = get_from_browser_cookie()  # DO NOT DO THIS

# Right: using a properly issued API token from FOUNDRY_TOKEN env var
token = os.environ.get("FOUNDRY_TOKEN")
```

**4. Dataset accessible in Foundry UI but HTTP 403 from API**

Dataset permissions and API token scopes are separate checks. A user can have read access to a dataset in the Foundry UI but the API token used by their script may not have the `api:read-data` scope, or the token may be issued for a different role context.
```
Verify:
  1. Your API token includes "api:read-data" scope
  2. The dataset permissions include your Foundry role
  3. You are connecting to the correct Foundry host
     (IL4 and IL5 have different URLs — mixing them causes 403 errors)
```

**5. Network proxy blocking Foundry API calls**

Government networks frequently proxy outbound HTTPS. The proxy may intercept the TLS connection and present its own certificate, breaking certificate pinning or SSL verification.
```python
# If you get SSL errors, check whether a proxy is in use
import os
print(os.environ.get("HTTPS_PROXY"))
print(os.environ.get("HTTP_PROXY"))

# If a proxy is configured, you may need to add the proxy's CA to your trust store
# Contact your IT office for the proxy CA certificate
```

---

## Best Practices

**Security**
- Never store tokens in notebooks, scripts, or version control. Use environment variables or Foundry's native secret management.
- Treat API tokens as passwords. A stolen Foundry token grants the same access as your user account.
- Log all programmatic access to datasets with classification markings.
- Rotate tokens before expiration to avoid production pipeline failures.

**IL4/IL5 Compliance**
- Access Foundry only from approved networks and approved devices. Your program's ATO defines these.
- Do not copy data from IL5 Foundry to IL4 systems. The Foundry platform enforces cross-domain controls, but your data handling practices must reinforce them.
- Session timeouts are mandatory, not optional. Implement inactivity detection in long-running notebook sessions.

**Operational Reliability**
- Validate token health at the start of every scheduled job. A job that fails after 2 hours of processing because the token expired mid-run wastes more time than the 2-second validation check at the beginning.
- Use foundry-dev-tools for local development. It handles token refresh automatically and stores credentials securely outside your codebase.
- Test authentication code against a non-production Foundry enrollment before deploying to production systems.

---

## Support and Resources

- Palantir Foundry documentation (requires enrollment access): `/docs` path on your Foundry instance
- DoD PKI documentation: https://public.cyber.mil/pki-pke/
- OpenSC project (PKCS#11 library): https://github.com/OpenSC/OpenSC
- foundry-dev-tools (local development): https://github.com/palantir/foundry-dev-tools
- Program-specific support: Contact your Foundry administrator or program IT office
- FedRAMP High authorization details: Palantir Federal Cloud Service authorization package (available to agency personnel via the FedRAMP marketplace)
