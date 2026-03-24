# Qlik Quickstart Guide

This guide supplements [`cac-piv-integration.md`](../cac-piv-integration.md)
with a condensed getting-started walkthrough for Qlik Sense on DoD networks.

## Prerequisites

- CAC/PIV card and reader
- Qlik tenant URL and API key (or OAuth client credentials)
- Python 3.9+ with packages from `requirements.txt`
- `qlik-sdk` or `websocket-client` installed
- Environment variables configured (see [`config/qlik_config.yaml`](../config/qlik_config.yaml))

## 1. Install Qlik SDK

```bash
pip install qlik-sdk requests websocket-client
```

## 2. Configure environment variables

```bash
export QLIK_TENANT_URL=https://your-tenant.us.qlikcloud.com
export QLIK_TENANT_ID=your-tenant-id
export QLIK_API_KEY=your-api-key
export QLIK_CLIENT_ID=your-client-id
export QLIK_AUTH_ENDPOINT=https://your-tenant.us.qlikcloud.com/oauth/authorize
export QLIK_TOKEN_ENDPOINT=https://your-tenant.us.qlikcloud.com/oauth/token
export PKCS11_LIB_PATH=/usr/lib/opensc-pkcs11.so
export CAC_CA_BUNDLE_PATH=/etc/pki/dod-ca-bundle.pem
```

## 3. Authenticate with CAC/PIV

```python
import sys
sys.path.insert(0, "security-compliance")  # from repo root

from auth.platform_adapters.qlik_adapter import QlikAdapter

adapter = QlikAdapter(
    config_path="platform-guides/qlik/config/qlik_config.yaml"
)
auth_result = adapter.authenticate()

if auth_result.success:
    print(f"Authenticated as: {auth_result.user_info['email']}")
else:
    print(f"Authentication failed: {auth_result.error}")
```

## 4. Use the Qlik REST API

```python
import requests

headers = {
    "Authorization": f"Bearer {auth_result.access_token}",
    "Content-Type": "application/json",
}
base = auth_result.tenant_url

# List apps
resp = requests.get(f"{base}/api/v1/items?resourceType=app", headers=headers)
resp.raise_for_status()
for item in resp.json().get("data", []):
    print(f"  {item['id']}: {item['name']}")
```

## 5. Connect to the Engine API (advanced)

For direct engine access (loading data, evaluating expressions):

```python
from qlik_sdk import Auth, Config, Qlik

config = Config(
    host=auth_result.tenant_url,
    auth_type=Auth.APIKey,
    api_key=auth_result.api_key,
)
qlik = Qlik(config=config)

app = qlik.apps.get("app-id-here")
with app.open():
    result = app.evaluate("Sum(Sales)")
    print(result)
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `401 Unauthorized` | API key expired or wrong tenant | Regenerate key in Qlik Management Console |
| `403 Forbidden` | Insufficient app permissions | Request access in Qlik catalog |
| WebSocket connection refused | Engine port 4747 blocked | Check firewall rules / virtual proxy settings |
| Certificate error | Missing DoD CA | Set `REQUESTS_CA_BUNDLE` env var |
| Virtual proxy 404 | Wrong proxy path | Confirm `/dod` prefix with Qlik admin |

## Next Steps

- Read the full [CAC/PIV integration guide](../cac-piv-integration.md)
- See [Qlik adapter source](../../../security-compliance/auth/platform_adapters/qlik_adapter.py)
- Review [visualization chapter](../../../chapters/10-visualization/README.md) for Qlik dashboard patterns
