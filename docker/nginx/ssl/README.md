# docker/nginx/ssl — Local Development TLS Certificates

This directory is intentionally empty in version control (tracked via `.gitkeep`).

## Purpose

Nginx is configured to load TLS certificates from this path:

```
ssl_certificate     /etc/nginx/ssl/nginx.crt;
ssl_certificate_key /etc/nginx/ssl/nginx.key;
```

Place your **local development** self-signed certificates here before starting
the Docker stack:

```bash
# Generate a self-signed cert valid for 365 days (local dev only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout docker/nginx/ssl/nginx.key \
  -out  docker/nginx/ssl/nginx.crt \
  -subj "/CN=ds-handbook.local"
```

## IMPORTANT — Do NOT use these certs in production

- Self-signed certificates are **not trusted by browsers** and must never be
  deployed to production or staging environments.
- Production certificates should be managed via a secrets manager (e.g.
  HashiCorp Vault, AWS ACM, Let's Encrypt) and injected at runtime — never
  committed to the repository.
- `*.crt`, `*.key`, `*.pem`, and `*.p12` files are listed in `.gitignore` to
  prevent accidental commits.
