# Navy Jupiter Quickstart Guide

This guide supplements [`cac-piv-integration.md`](../cac-piv-integration.md)
with a condensed getting-started walkthrough for Navy Jupiter on DoD networks.

## Prerequisites

- CAC/PIV card and reader
- Navy Jupiter workspace access (coordinate with your command's data office)
- Python 3.9+ with packages from `requirements.txt`
- Environment variables configured (see [`config/navy_jupiter_config.yaml`](../config/navy_jupiter_config.yaml))
- VPN connected to appropriate DoD network segment

## 1. Install PKCS#11 dependencies

```bash
# RHEL/CentOS (common in DoD environments)
sudo yum install opensc pcsc-lite pcsc-lite-libs coolkey

# Ubuntu/Debian
sudo apt-get install opensc pcscd libpcsclite-dev

# Start PC/SC daemon
sudo systemctl enable --now pcscd
```

Verify card is recognized:

```bash
opensc-tool --list-readers
pkcs11-tool --module /usr/lib64/opensc-pkcs11.so --list-slots
```

## 2. Configure environment variables

```bash
export NAVY_JUPITER_BASE_URL=https://jupiter.navy.mil
export NAVY_JUPITER_CLIENT_ID=your_client_id
export NAVY_JUPITER_AUTH_ENDPOINT=https://sso.navy.mil/oauth/authorize
export NAVY_JUPITER_TOKEN_ENDPOINT=https://sso.navy.mil/oauth/token
export NAVY_JUPITER_REDIRECT_URI=https://your-app.navy.mil/callback
export PKCS11_LIB_PATH=/usr/lib64/opensc-pkcs11.so
export CAC_CA_BUNDLE_PATH=/etc/pki/dod-ca-bundle.pem
```

## 3. Authenticate with CAC/PIV

```python
import sys
sys.path.insert(0, "security-compliance")  # from repo root

from auth.platform_adapters.navy_jupiter_adapter import NavyJupiterAdapter

adapter = NavyJupiterAdapter(
    config_path="platform-guides/navy-jupiter/config/navy_jupiter_config.yaml"
)
auth_result = adapter.authenticate()

if auth_result.success:
    print(f"Authenticated as: {auth_result.user_info['email']}")
    print(f"Classification context: {auth_result.classification_level}")
else:
    print(f"Authentication failed: {auth_result.error}")
```

## 4. Spawn a JupyterHub server

```python
import requests

headers = {"Authorization": f"token {auth_result.jupyterhub_token}"}
base = auth_result.jupyterhub_url

# Start server
resp = requests.post(f"{base}/api/users/{auth_result.username}/server", headers=headers)
resp.raise_for_status()
print(f"Server starting at: {base}/user/{auth_result.username}/")
```

## 5. Classification banner requirement

Navy Jupiter requires all notebooks and outputs to include classification banners.
Use the helper from the handbook:

```python
from security_compliance.multi_classification.models.bell_lapadula import (
    ClassificationLevel,
    add_classification_banner,
)

# Add to the top of any output
banner = add_classification_banner(ClassificationLevel.UNCLASSIFIED)
print(banner)
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `pcscd` not running | Service stopped | `sudo systemctl start pcscd` |
| `CKR_TOKEN_NOT_PRESENT` | CAC not inserted | Insert card and retry |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Missing DoD CA | Point `CAC_CA_BUNDLE_PATH` to correct bundle |
| `403 Access Denied` | Groups not provisioned | Contact platform admin to add groups |
| Server spawn timeout | Resource limits | Reduce memory/CPU in config or contact admin |

## Next Steps

- Read the full [CAC/PIV integration guide](../cac-piv-integration.md)
- See [Navy Jupiter adapter source](../../../security-compliance/auth/platform_adapters/navy_jupiter_adapter.py)
- Review [classification handling](../../../security-compliance/multi-classification/) for CUI/FOUO content
