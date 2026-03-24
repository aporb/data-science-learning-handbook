"""
Chapter 01: Authentication Patterns
=====================================
CAC/PIV-based authentication and token management for federal data science platforms.

Federal platforms use two authentication modes that practitioners must understand:

  1. Interactive CAC/PIV — The user inserts their CAC card, enters a PIN, and
     the platform reads the certificate from the card reader. This is the standard
     login method on desktops with a card reader attached.

  2. Service/token-based — For scheduled jobs, notebooks running unattended, or
     scripts that run in CI/CD pipelines, you use a pre-issued token derived from
     a prior CAC authentication. Tokens expire. Managing them is part of the job.

This file shows both patterns and the token lifecycle management code that every
practitioner who runs automated jobs on federal platforms eventually needs.

Platform coverage:
  - Databricks (Personal Access Token pattern)
  - Palantir Foundry (Bearer token + foundry-dev-tools pattern)
  - Qlik Cloud Government (API key pattern)
  - Common PKI/CAC certificate reading via PyKCS11

Prerequisites:
  pip install PyKCS11 cryptography requests python-dotenv

Note: These patterns require network access to the target platform. In air-gapped
or semi-isolated environments, consult your system administrator for the approved
token issuance workflow.
"""

import os
import sys
import base64
import json
import time
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# Configure logging — never log tokens or credentials, only events
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("auth_patterns")


# ============================================================
# SECTION 1: CAC/PIV CERTIFICATE READING
# Physical CAC card reading via PKCS#11 interface.
# Requires: OpenSC installed and a CAC card reader connected.
# ============================================================

def read_cac_certificate() -> Optional[bytes]:
    """
    Read the authentication certificate from an inserted CAC card.

    Returns the DER-encoded certificate bytes, or None if no card is detected.

    This is the first step in any interactive CAC authentication flow. The
    certificate identifies the user (via embedded EDIPI in the Subject field)
    and is used to verify the digital signature produced during authentication.

    Hardware requirement: CAC card reader with OpenSC PKCS#11 library installed.
    On Windows: c:/Windows/System32/opensc-pkcs11.dll
    On Linux/Mac: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
    """
    try:
        from PyKCS11 import PyKCS11Lib, PyKCS11Error, CKO_CERTIFICATE, CKA_VALUE

        lib = PyKCS11Lib()

        # Adjust this path for your OS and OpenSC installation
        pkcs11_lib_path = os.environ.get(
            "PKCS11_LIB_PATH",
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
        )

        try:
            lib.load(pkcs11_lib_path)
        except PyKCS11Error as e:
            logger.error(
                "Failed to load PKCS#11 library at %s. "
                "Verify OpenSC is installed: %s", pkcs11_lib_path, e
            )
            return None

        slots = lib.getSlotList(tokenPresent=True)
        if not slots:
            logger.warning(
                "No CAC card detected. Insert your card and try again."
            )
            return None

        # Use the first available slot (most desktops have one reader)
        slot = slots[0]
        session = lib.openSession(slot)

        # Find certificate objects on the card
        cert_objects = session.findObjects([(CKO_CERTIFICATE, True)])

        if not cert_objects:
            logger.error(
                "No certificate found on CAC card. Card may not be properly initialized."
            )
            session.closeSession()
            return None

        # Read the certificate value (DER-encoded bytes)
        cert_value = session.getAttributeValue(cert_objects[0], [CKA_VALUE])
        cert_bytes = bytes(cert_value[0])

        session.closeSession()
        logger.info(
            "CAC certificate read successfully (%d bytes)", len(cert_bytes)
        )
        return cert_bytes

    except ImportError:
        logger.error(
            "PyKCS11 not installed. Run: pip install PyKCS11"
        )
        return None


def extract_edipi_from_certificate(cert_der_bytes: bytes) -> Optional[str]:
    """
    Extract the DoD Electronic Data Interchange Personal Identifier (EDIPI)
    from a CAC certificate.

    The EDIPI is the 10-digit identifier embedded in the Subject Alternative Name
    or the Subject CN of the certificate in the format:
        CN=LASTNAME.FIRSTNAME.MIDDLENAME.EDIPI

    This is used as the unique user identifier across DoD systems.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(cert_der_bytes, default_backend())

        # Try Subject CN first — format: LAST.FIRST.MIDDLE.EDIPI
        subject_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if subject_cn:
            cn_value = subject_cn[0].value
            parts = cn_value.split(".")
            # EDIPI is the last 10-digit numeric segment
            for part in reversed(parts):
                if part.isdigit() and len(part) == 10:
                    return part

        logger.warning(
            "EDIPI not found in certificate CN. Inspect Subject manually."
        )
        return None

    except ImportError:
        logger.error("cryptography package not installed: pip install cryptography")
        return None
    except Exception as e:
        logger.error("Error parsing certificate: %s", e)
        return None


# ============================================================
# SECTION 2: DATABRICKS TOKEN MANAGEMENT
# Personal Access Tokens (PATs) are the standard auth method
# for Databricks API access in DoD environments.
# ============================================================

class DatabricksTokenManager:
    """
    Manages Databricks Personal Access Tokens for API access.

    In government Databricks workspaces (Advana, Navy Jupiter, standalone
    GovCloud), users authenticate interactively via CAC/SSO and then generate
    Personal Access Tokens for programmatic access.

    Token lifecycle:
    - Created via Databricks UI (User Settings > Access Tokens) or API
    - Maximum lifetime is workspace-configured (typically 90 days on DoD systems)
    - Stored in environment variables — never in code or notebooks
    - Rotated before expiration to avoid pipeline failures

    Environment variables required:
        DATABRICKS_HOST  — e.g., https://adb-xxx.azuredatabricks.net
        DATABRICKS_TOKEN — the PAT value (starts with "dapi")
    """

    def __init__(self):
        self.host = os.environ.get("DATABRICKS_HOST")
        self.token = os.environ.get("DATABRICKS_TOKEN")

    def validate_connection(self) -> bool:
        """
        Test that the current token is valid and the workspace is reachable.
        Run this at the start of any job that will use the token.
        """
        if not self.host or not self.token:
            logger.error(
                "DATABRICKS_HOST and DATABRICKS_TOKEN environment variables must be set. "
                "Never hardcode these values."
            )
            return False

        try:
            import requests
            response = requests.get(
                f"{self.host}/api/2.0/clusters/list",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=15
            )
            if response.status_code == 200:
                logger.info(
                    "Databricks connection validated. Host: %s", self.host
                )
                return True
            elif response.status_code == 403:
                logger.error(
                    "Databricks token is invalid or expired. "
                    "Generate a new token at: %s/settings/user/developer/access-tokens",
                    self.host
                )
                return False
            else:
                logger.error(
                    "Unexpected response from Databricks: %d", response.status_code
                )
                return False
        except ImportError:
            logger.error("requests not installed: pip install requests")
            return False
        except Exception as e:
            logger.error("Connection error: %s", e)
            return False

    def get_token_expiry(self) -> Optional[datetime]:
        """
        Query the Databricks API for the current token's expiration date.

        Returns the expiration datetime, or None if the token has no expiry
        or if the query fails.

        Use this in a health-check job that runs weekly to alert before
        token expiration disrupts production pipelines.
        """
        if not self.host or not self.token:
            return None

        try:
            import requests
            response = requests.get(
                f"{self.host}/api/2.0/token/list",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=15
            )

            if response.status_code != 200:
                return None

            tokens = response.json().get("token_infos", [])

            # Find the current token — match by token value hash
            # (Databricks returns token info without the full value for security)
            # If only one token exists, it's the current one
            if len(tokens) == 1:
                expiry_ms = tokens[0].get("expiry_time", -1)
                if expiry_ms > 0:
                    return datetime.fromtimestamp(
                        expiry_ms / 1000, tz=timezone.utc
                    )

            return None

        except Exception as e:
            logger.warning("Could not retrieve token expiry: %s", e)
            return None

    def check_token_health(self, warning_days: int = 14) -> Dict[str, Any]:
        """
        Check token health and warn if expiration is within warning_days.

        Returns a dict with:
            - valid: bool — whether the token currently works
            - days_remaining: int or None — days until expiration
            - action_required: bool — True if rotation needed soon

        Use this in a monitoring job:
            health = manager.check_token_health(warning_days=14)
            if health["action_required"]:
                send_alert("Databricks token expiring soon")
        """
        valid = self.validate_connection()
        expiry = self.get_token_expiry()

        days_remaining = None
        action_required = False

        if expiry:
            delta = expiry - datetime.now(tz=timezone.utc)
            days_remaining = delta.days
            action_required = days_remaining <= warning_days

            if action_required:
                logger.warning(
                    "Databricks token expires in %d days. Rotate before expiration "
                    "to avoid pipeline failure. See: %s/settings/user/developer/access-tokens",
                    days_remaining, self.host
                )

        return {
            "valid": valid,
            "days_remaining": days_remaining,
            "action_required": action_required,
            "host": self.host,
            "checked_at": datetime.now(tz=timezone.utc).isoformat()
        }


# ============================================================
# SECTION 3: PALANTIR FOUNDRY TOKEN MANAGEMENT
# Foundry uses Bearer tokens for API access.
# In Code Workspaces, the token is injected automatically.
# For local dev, use foundry-dev-tools or a manually issued token.
# ============================================================

class FoundryTokenManager:
    """
    Manages Palantir Foundry API tokens for local development and
    automated workflows.

    Two modes:
    1. Code Workspace (in-browser): No token management needed — the
       workspace injects credentials automatically via the transforms context.

    2. Local development (foundry-dev-tools): Tokens are managed via the
       foundry-dev-tools configuration. Initial auth is done interactively
       via browser; subsequent requests use cached tokens.

    Environment variable (for manual token approach):
        FOUNDRY_TOKEN — Bearer token from Foundry's token management UI

    Reference: https://github.com/palantir/foundry-dev-tools
    """

    def __init__(self):
        self.token = os.environ.get("FOUNDRY_TOKEN")
        self.host = os.environ.get("FOUNDRY_HOST")  # e.g., https://yourstack.palantirfoundry.com

    def validate_connection(self) -> bool:
        """
        Test the Foundry token via the /api/v1/userinfo endpoint.
        """
        if not self.token or not self.host:
            logger.error(
                "Set FOUNDRY_TOKEN and FOUNDRY_HOST environment variables. "
                "In a Code Workspace, these are injected automatically."
            )
            return False

        try:
            import requests
            response = requests.get(
                f"{self.host}/api/v1/userinfo",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=15
            )

            if response.status_code == 200:
                user_info = response.json()
                logger.info(
                    "Foundry connection validated. User: %s",
                    user_info.get("username", "unknown")
                )
                return True
            elif response.status_code == 401:
                logger.error(
                    "Foundry token is invalid or expired. "
                    "Re-authenticate via the Foundry UI or run: "
                    "foundry-dev-tools login"
                )
                return False
            else:
                logger.error(
                    "Unexpected Foundry response: %d", response.status_code
                )
                return False

        except ImportError:
            logger.error("requests not installed: pip install requests")
            return False
        except Exception as e:
            logger.error("Foundry connection error: %s", e)
            return False

    def use_foundry_dev_tools(self) -> bool:
        """
        Authenticate using foundry-dev-tools for local development.

        foundry-dev-tools handles token refresh automatically and stores
        credentials in ~/.foundry/credentials (not in your code).

        Install: pip install foundry-dev-tools
        First-time setup: foundry-dev-tools login

        Returns True if foundry-dev-tools is available and configured.
        """
        try:
            from foundry_dev_tools import FoundryContext
            ctx = FoundryContext()
            logger.info(
                "foundry-dev-tools FoundryContext initialized. "
                "Token management is handled automatically."
            )
            return True
        except ImportError:
            logger.error(
                "foundry-dev-tools not installed. "
                "Install with: pip install foundry-dev-tools"
            )
            return False
        except Exception as e:
            logger.error(
                "foundry-dev-tools context error: %s. "
                "Run: foundry-dev-tools login", e
            )
            return False


# ============================================================
# SECTION 4: QLIK API KEY MANAGEMENT
# Qlik Cloud Government uses API keys for programmatic access.
# Keys are created in the Qlik Management Console.
# ============================================================

class QlikTokenManager:
    """
    Manages Qlik Cloud Government API keys.

    Qlik API keys are created in the Qlik Management Console under
    Security > API Keys. Each key is associated with a specific user
    and has an optional expiration date.

    In government Qlik tenants (typically hosted on Advana or as
    standalone GovCloud deployments), API keys are the primary method
    for automated access — CAC/SSO is for interactive browser sessions.

    Environment variables:
        QLIK_TENANT_URL — e.g., https://your-tenant.us.qlikcloud.com
        QLIK_API_KEY    — the API key value from QMC
    """

    def __init__(self):
        self.tenant_url = os.environ.get("QLIK_TENANT_URL")
        self.api_key = os.environ.get("QLIK_API_KEY")

    def validate_connection(self) -> bool:
        """
        Validate the API key against the Qlik /api/v1/users/me endpoint.
        """
        if not self.tenant_url or not self.api_key:
            logger.error(
                "Set QLIK_TENANT_URL and QLIK_API_KEY environment variables."
            )
            return False

        try:
            import requests
            response = requests.get(
                f"{self.tenant_url}/api/v1/users/me",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=15
            )

            if response.status_code == 200:
                user = response.json()
                logger.info(
                    "Qlik connection validated. User: %s (%s)",
                    user.get("name", "unknown"), user.get("email", "unknown")
                )
                return True
            elif response.status_code == 401:
                logger.error(
                    "Qlik API key is invalid or expired. "
                    "Generate a new key in the Qlik Management Console."
                )
                return False
            else:
                logger.error(
                    "Unexpected Qlik response: %d %s",
                    response.status_code, response.text[:200]
                )
                return False

        except ImportError:
            logger.error("requests not installed: pip install requests")
            return False
        except Exception as e:
            logger.error("Qlik connection error: %s", e)
            return False


# ============================================================
# SECTION 5: ENVIRONMENT VALIDATION WITH AUTH CHECKS
# Extends the basic environment check from 01_platform_connections.py
# with token validity testing for all configured platforms.
# ============================================================

def validate_auth_environment() -> Dict[str, Any]:
    """
    Run authentication validation across all configured platforms.

    Returns a dict summarizing the auth status of each platform
    for which credentials are configured.

    Add this to the top of production notebooks or job scripts:

        from chapters.code_examples.python.auth_patterns import validate_auth_environment
        status = validate_auth_environment()
        for platform, result in status.items():
            if not result["valid"]:
                raise RuntimeError(f"{platform} auth failed: {result['error']}")

    This catches expired tokens before the job runs, rather than
    mid-pipeline when a silent failure is harder to diagnose.
    """
    results = {}

    # Databricks (Advana, Jupiter, standalone GovCloud)
    if os.environ.get("DATABRICKS_HOST") and os.environ.get("DATABRICKS_TOKEN"):
        mgr = DatabricksTokenManager()
        health = mgr.check_token_health()
        results["databricks"] = {
            "valid": health["valid"],
            "days_remaining": health["days_remaining"],
            "action_required": health["action_required"],
            "error": None if health["valid"] else "Token invalid or expired"
        }
    else:
        results["databricks"] = {
            "valid": False,
            "days_remaining": None,
            "action_required": False,
            "error": "DATABRICKS_HOST or DATABRICKS_TOKEN not set"
        }

    # Palantir Foundry
    if os.environ.get("FOUNDRY_TOKEN") and os.environ.get("FOUNDRY_HOST"):
        mgr = FoundryTokenManager()
        valid = mgr.validate_connection()
        results["foundry"] = {
            "valid": valid,
            "days_remaining": None,  # Foundry token expiry not exposed via API
            "action_required": not valid,
            "error": None if valid else "Foundry token invalid or expired"
        }
    else:
        results["foundry"] = {
            "valid": False,
            "days_remaining": None,
            "action_required": False,
            "error": "FOUNDRY_TOKEN or FOUNDRY_HOST not set"
        }

    # Qlik Cloud Government
    if os.environ.get("QLIK_TENANT_URL") and os.environ.get("QLIK_API_KEY"):
        mgr = QlikTokenManager()
        valid = mgr.validate_connection()
        results["qlik"] = {
            "valid": valid,
            "days_remaining": None,
            "action_required": not valid,
            "error": None if valid else "Qlik API key invalid or expired"
        }
    else:
        results["qlik"] = {
            "valid": False,
            "days_remaining": None,
            "action_required": False,
            "error": "QLIK_TENANT_URL or QLIK_API_KEY not set"
        }

    # Summary to console
    print("\n=== Authentication Status ===")
    for platform, result in results.items():
        status_symbol = "OK " if result["valid"] else "FAIL"
        days_note = (
            f" ({result['days_remaining']}d remaining)"
            if result.get("days_remaining") is not None
            else ""
        )
        warn_note = " *** ROTATE SOON ***" if result.get("action_required") and result["valid"] else ""
        print(f"  [{status_symbol}] {platform.upper()}{days_note}{warn_note}")
        if result.get("error") and not result["valid"]:
            print(f"         Error: {result['error']}")
    print()

    return results


def load_env_file(env_path: Optional[str] = None) -> None:
    """
    Load environment variables from a .env file for local development.

    Production systems should use the platform's native secret management
    (Databricks secrets, Foundry secret stores, etc.). The .env approach
    is for local development only — never commit a .env file to version control.

    Standard .env file format:
        DATABRICKS_HOST=https://adb-xxx.azuredatabricks.net
        DATABRICKS_TOKEN=dapi1234567890abcdef
        FOUNDRY_HOST=https://yourstack.palantirfoundry.com
        FOUNDRY_TOKEN=bearer_token_here
        QLIK_TENANT_URL=https://your-tenant.us.qlikcloud.com
        QLIK_API_KEY=api_key_here

    Usage:
        load_env_file()         # loads .env in current directory
        load_env_file("~/.federal_ds_env")  # loads from custom path
    """
    try:
        from dotenv import load_dotenv
        path = Path(env_path).expanduser() if env_path else Path(".env")
        if path.exists():
            load_dotenv(path)
            logger.info("Loaded environment variables from %s", path)
        else:
            logger.warning(
                ".env file not found at %s. "
                "Set environment variables manually or specify a different path.",
                path
            )
    except ImportError:
        logger.warning(
            "python-dotenv not installed. "
            "Install with: pip install python-dotenv, or set env vars manually."
        )


# ============================================================
# MAIN: Run all auth pattern demonstrations
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Chapter 01: Authentication Patterns")
    print("=" * 60)
    print()

    # Optional: load from .env file for local development
    # load_env_file()

    print("--- Authentication Environment Validation ---")
    status = validate_auth_environment()

    print("--- CAC Certificate Reading (requires hardware card reader) ---")
    cert_bytes = read_cac_certificate()
    if cert_bytes:
        edipi = extract_edipi_from_certificate(cert_bytes)
        if edipi:
            print(f"  EDIPI extracted: {edipi}")
        else:
            print("  Certificate read successfully but EDIPI not found in CN.")
    else:
        print("  No CAC card detected or PyKCS11 unavailable.")
        print("  For token-based authentication, set env vars and re-run.")

    print("\nFor platform-specific auth setup instructions, see:")
    print("  platform-guides/<platform>/cac-piv-integration.md")
