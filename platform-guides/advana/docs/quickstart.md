# Advana Quickstart Guide

This guide supplements the full [`cac-piv-integration.md`](../cac-piv-integration.md)
with a condensed getting-started walkthrough.

## Prerequisites

- CAC/PIV card and reader
- DoD-issued certificate (not expired, not revoked)
- Python 3.9+ with the packages from `requirements.txt` installed
- Network access to the Advana platform endpoints
- Environment variables configured (see [`config/advana_config.yaml`](../config/advana_config.yaml))

## 1. Install PKCS#11 dependencies

```bash
# macOS
brew install opensc

# RHEL/CentOS
sudo yum install opensc pcsc-lite pcsc-lite-libs

# Ubuntu/Debian
sudo apt-get install opensc pcscd libpcsclite-dev
```

Verify your CAC reader is detected:

```bash
opensc-tool --list-readers
pkcs11-tool --list-slots
```

## 2. Configure environment variables

```bash
export PKCS11_LIB_PATH=/usr/lib/opensc-pkcs11.so  # adjust for your OS
export ADVANA_CLIENT_ID=your_client_id
export ADVANA_AUTH_ENDPOINT=https://advana.example.mil/oauth/authorize
export ADVANA_TOKEN_ENDPOINT=https://advana.example.mil/oauth/token
export ADVANA_REDIRECT_URI=https://your-app.example.mil/callback
export CAC_CA_BUNDLE_PATH=/etc/pki/dod-ca-bundle.pem
```

Or copy `.env.example` to `.env` and fill in the values.

## 3. Run authentication

```python
import sys
sys.path.insert(0, "security-compliance")  # from repo root

from auth.platform_adapters.advana_adapter import AdvanaAdapter

adapter = AdvanaAdapter(config_path="platform-guides/advana/config/advana_config.yaml")
auth_result = adapter.authenticate()

if auth_result.success:
    print(f"Authenticated as: {auth_result.user_info['email']}")
    token = auth_result.access_token
else:
    print(f"Authentication failed: {auth_result.error}")
```

## 4. Use the token in API calls

```python
import requests

headers = {"Authorization": f"Bearer {token}"}
response = requests.get("https://advana.example.mil/api/v1/datasets", headers=headers)
response.raise_for_status()
print(response.json())
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `opensc-tool: no readers` | Reader not connected | Connect CAC reader and restart pcscd |
| `CKR_PIN_LOCKED` | Wrong PIN entered too many times | Contact your security officer to unlock card |
| `certificate verify failed` | CA bundle missing or outdated | Update `CAC_CA_BUNDLE_PATH` |
| `401 Unauthorized` | Token expired | Re-authenticate to get a fresh token |
| `Connection refused` | Proxy not configured | Set `HTTPS_PROXY` environment variable |

## Next Steps

- Read the full [CAC/PIV integration guide](../cac-piv-integration.md) for advanced configuration
- See the [Advana adapter source code](../../../security-compliance/auth/platform_adapters/advana_adapter.py)
- Review [session security](../../../security-compliance/sessions/session_security.py) for production hardening
