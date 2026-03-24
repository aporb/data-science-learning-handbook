# Local Development Environment

This handbook includes a Docker Compose stack that mirrors federal platform constraints on your local machine. It is designed to give practitioners a sandboxed environment where code examples and exercises run under conditions similar to what they will encounter on Advana, Databricks, Navy Jupiter, and other federal platforms.

---

## What It Includes

| Service | Purpose | Port |
|---------|---------|------|
| **Jupyter** | JupyterLab notebooks for running chapter code examples | 8888 |
| **MLflow** | Experiment tracking and model registry (Chapter 9, 11) | 5000 |
| **PostgreSQL** | Relational database for data exercises | 5432 |
| **Redis** | Caching layer and message broker | 6379 |
| **Nginx** | Reverse proxy with SSL termination | 80/443 |
| **Prometheus** | Metrics collection for monitoring examples | 9090 |
| **Grafana** | Dashboard visualization for monitoring examples | 3000 |
| **CAC Auth Service** | Simulated CAC/PIV authentication service | 8443 |

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2+)
- At least 8GB of available RAM

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/aporb/data-science-learning-handbook.git
cd data-science-learning-handbook

# Copy the environment template
cp .env.example .env

# Edit .env with your configuration (API keys, credentials)
# See env-example.txt for platform-specific variables

# Start all services
docker compose up -d

# Verify services are running
docker compose ps
```

JupyterLab will be available at `http://localhost:8888`. MLflow at `http://localhost:5000`.

---

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

- **Database credentials** — PostgreSQL user, password, database name
- **MLflow settings** — Artifact storage location, tracking URI
- **Platform API keys** — Databricks tokens, Qlik API keys (optional, for platform-specific exercises)
- **CAC/PIV paths** — Certificate paths for the authentication service simulator

See `env-example.txt` for a commented reference of all available variables.

### Service-Specific Configuration

Each service has configuration files in `docker/`:

- `docker/jupyter/` — Notebook configuration
- `docker/mlflow/` — MLflow Nginx config
- `docker/nginx/` — Reverse proxy configuration
- `docker/prometheus/` — Metrics and alert rules
- `docker/grafana/` — Dashboard provisioning
- `docker/vault/` — Secrets management configuration
- `docker/redis/` — Redis configuration

---

## Common Operations

```bash
# Stop all services
docker compose down

# Rebuild after Dockerfile changes
docker compose build

# View logs for a specific service
docker compose logs -f jupyter

# Reset everything (including data volumes)
docker compose down -v
```

---

## Troubleshooting

**Services fail to start:** Check that port 8888, 5000, 5432, and 6379 are not in use by other applications.

**Out of memory:** The full stack requires ~6-8GB RAM. If constrained, start only the services you need:

```bash
docker compose up -d jupyter mlflow postgres
```

**Jupyter kernel dies:** Increase Docker memory allocation in Docker Desktop settings.
