# Local learning environment

Use only public or synthetic data. This lab is not an IL4, IL5, IL6, CAC, or cross-domain accredited environment.
Do not add agency credentials, operational records, CUI, or classified material.

## Choose a setup

The small learning profile runs one authenticated Jupyter notebook on Python 3.11.
It uses a digest-pinned base image and hash-locked packages.
Chapter files mount read-only. Save your own notebooks in the writable `notebooks/` directory inside Jupyter.
No government login or real API key is required.

The separate legacy reference stack has 13 services. It demonstrates architecture patterns but requires additional configuration.
It is not the recommended first-run environment or a production deployment.

## Python-only setup

From the repository root:

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-learning.txt
python -m pytest tests -q
python scripts/check_handbook.py
```

This profile does not install Spark, Foundry libraries, GPU frameworks, or the complete security infrastructure.
Examples for those systems require the indicated authorized platform and approved dependencies.
Do not install this public lock directly into a managed government environment.

## Small Docker lab

Install Docker and Compose v2. From the repository root:

```bash
docker compose -p fdsh-learning -f compose.learning.yml --profile learning up --build -d
docker compose -p fdsh-learning -f compose.learning.yml --profile learning ps
```

Open `http://127.0.0.1:8888`. Jupyter requires its generated token.
Retrieve the login URL on your own machine:

```bash
docker compose -p fdsh-learning -f compose.learning.yml --profile learning logs notebook
```

Treat the token as a local credential. Do not paste it into issues, reports, or agent conversations.
Do not disable token authentication, XSRF protection, or same-origin checks.
The container listens on all container interfaces so Docker can route traffic. The published host port binds only to loopback.

If port 8888 is occupied, set `HANDBOOK_NOTEBOOK_PORT` before the Compose command.
Use the selected port in the browser URL. Do not change the binding to `0.0.0.0`.

Stop only this lab:

```bash
docker compose -p fdsh-learning -f compose.learning.yml --profile learning down
```

This preserves the named notebook volume. Adding `--volumes` deletes those notebooks. Export your work before deleting it.
Containers can reach the network. Loopback publication is not an air gap or a certification of the host.

## Legacy reference stack

The 13 service definitions are in `docker-compose.yml` under the explicit `reference` profile:
Jupyter, MLflow, PostgreSQL, Redis, Nginx, Prometheus, Grafana, scanner, docs, CAC simulator, Consul, Vault, and Vault initialization.
Every published port binds to loopback. These examples still require separate dependency, certificate, and configuration review.

Validate the model without starting services:

```bash
docker compose --profile reference config --quiet
```

Do not start all reference services merely to run a chapter example.
If you study a particular service, select it explicitly after reviewing its Dockerfile, mounts, dependencies, and configuration.
The CAC service is a simulator. It does not establish a real clearance or identity assurance.

The Vault example requires provisioned TLS material and a trusted CA at `/vault/tls/ca.crt`.
The certificate must cover the `vault` service hostname. Certificate verification stays enabled.
Bootstrap keys and the root token must remain in protected files, not terminal logs.
The example is not a production Vault bootstrap or recovery design.

## Dependencies and verification

`requirements-learning.in` declares the limited learning profile. `requirements-learning.txt` locks resolved packages and hashes.
The older `requirements.txt` and `environment.yml` cover broader reference environments, not this tested subset.

For a planned dependency change, resolve a fresh lock in an isolated environment:

```bash
uv pip compile --python-version 3.11 --universal --generate-hashes requirements-learning.in -o requirements-learning.txt
```

Run the tests and a current dependency advisory scan after each change.
A successful test run does not prove the absence of vulnerabilities or authorization for government workloads.
