"""
Chapter 11: Deployment & Scaling
Code Examples: API Serving, Kubernetes Deployment, Blue-Green & Canary Patterns

This module covers:
  1. Production-hardened FastAPI app with health probes and metrics
  2. Kubernetes manifests as Python-generated YAML (RKE2/OpenShift compatible)
  3. Blue-green deployment swap logic
  4. Canary deployment with traffic splitting
  5. Model drift monitoring and automated alerting

Platform targets: RKE2 (DoD standard), OpenShift (FedRAMP Moderate/High),
                  GovCloud EKS, Databricks (for comparison)

Runtime note: Kubernetes manifest generation runs anywhere (no cluster needed).
              The FastAPI sections require: pip install fastapi uvicorn pydantic prometheus-client
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import yaml  # pip install pyyaml

# ---------------------------------------------------------------------------
# Section 1: Production FastAPI with Health Probes, Metrics, and Audit Log
# ---------------------------------------------------------------------------
# The Chapter 11 README shows a minimal FastAPI app. This extends it with
# the three things every production government deployment needs:
#   - /health and /readiness endpoints (Kubernetes liveness + readiness probes)
#   - Prometheus metrics for the ops team's Grafana dashboard
#   - Structured JSON audit log for the SIEM (Splunk, ELK, Chronicle)
#
# The distinction between liveness and readiness matters:
#   Liveness: "Is the container alive?" — if this fails, Kubernetes restarts the pod
#   Readiness: "Can this pod serve traffic?" — if this fails, pod is removed from Service
# A model that is loading its artifact should fail readiness but pass liveness.
# A crashed container should fail both.


def create_production_app(model_uri: str | None = None):
    """
    Build a production FastAPI application with full observability.

    This is the version you'd actually deploy in IL4. The simplified version
    in 01_deployment_patterns.py is fine for prototyping; this one handles
    the ops team's requirements.
    """
    try:
        import mlflow.pyfunc
        import pandas as pd
        from fastapi import FastAPI, HTTPException, Request, Security
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
        from prometheus_client import Counter, Gauge, Histogram, generate_latest
        from pydantic import BaseModel, Field
        from starlette.responses import Response
    except ImportError:
        raise ImportError(
            "Install dependencies: pip install fastapi uvicorn pydantic prometheus-client mlflow"
        )

    # -------------------------------------------------------------------
    # Prometheus metrics — these are scraped by the cluster's monitoring
    # stack (Prometheus + Grafana). Standard in OpenShift and RKE2 clusters
    # that have the monitoring operator installed.
    # -------------------------------------------------------------------
    INFERENCE_REQUESTS = Counter(
        "inference_requests_total",
        "Total inference requests",
        ["status", "risk_tier"],
    )
    INFERENCE_LATENCY = Histogram(
        "inference_latency_seconds",
        "Inference request latency",
        buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
    )
    MODEL_LOAD_STATUS = Gauge(
        "model_load_status",
        "1 if model is loaded and ready, 0 otherwise",
    )
    PREDICTION_SCORE = Histogram(
        "prediction_score",
        "Distribution of model output scores",
        buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
    )

    app = FastAPI(
        title="Maintenance Risk Scoring API",
        version="1.0.0",
        # In production (ENVIRONMENT=production), disable Swagger UI —
        # it's an unnecessary attack surface and not useful to end users.
        docs_url="/docs" if os.getenv("ENVIRONMENT") != "production" else None,
        redoc_url=None,
    )

    # CORS: lock down to known origins in production
    allowed_origins = os.getenv(
        "ALLOWED_ORIGINS",
        "https://dashboard.don.mil,https://qlik.don.mil"
    ).split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    security = HTTPBearer()

    # Model state — shared across requests
    _state: dict[str, Any] = {
        "model": None,
        "model_uri": model_uri,
        "loaded_at": None,
        "version": None,
    }

    def verify_token(
        credentials: HTTPAuthorizationCredentials = Security(security),
    ) -> str:
        """
        Validate Bearer token against the configured secret.
        Returns the token as requestor identity (or decode a JWT for real identity).

        401 = no credentials (HTTPBearer raises this automatically)
        403 = credentials present but invalid
        """
        expected = os.getenv("INFERENCE_API_TOKEN")
        if expected and credentials.credentials != expected:
            raise HTTPException(status_code=403, detail="Invalid token")
        return credentials.credentials

    # -------------------------------------------------------------------
    # Startup: load model once, not per-request
    # -------------------------------------------------------------------
    @app.on_event("startup")
    async def startup():
        if _state["model_uri"]:
            try:
                _state["model"] = mlflow.pyfunc.load_model(_state["model_uri"])
                _state["loaded_at"] = datetime.now(timezone.utc).isoformat()
                MODEL_LOAD_STATUS.set(1)
                print(f"Model loaded from: {_state['model_uri']}")
            except Exception as exc:
                MODEL_LOAD_STATUS.set(0)
                print(f"WARNING: Model failed to load: {exc}")
                # Don't crash startup — let readiness probe fail instead.
                # This lets the ops team diagnose the issue without a restart loop.
        else:
            # Demo mode: no model URI provided
            MODEL_LOAD_STATUS.set(0)

    # -------------------------------------------------------------------
    # Probe endpoints
    # -------------------------------------------------------------------
    @app.get("/health", include_in_schema=False)
    async def liveness():
        """
        Liveness probe. Returns 200 as long as the process is running.
        Kubernetes kills and restarts the pod if this returns non-200.
        This should ONLY fail for truly unrecoverable states (OOM, deadlock).
        A model that hasn't loaded yet should NOT fail liveness.
        """
        return {"status": "alive", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.get("/readiness", include_in_schema=False)
    async def readiness():
        """
        Readiness probe. Returns 200 only when the model is loaded.
        Kubernetes removes this pod from the Service endpoint list if 503.
        During a rolling deployment, new pods pass readiness before old ones are terminated.
        """
        if _state["model"] is None and _state["model_uri"] is not None:
            raise HTTPException(status_code=503, detail="Model not loaded")
        return {
            "status": "ready",
            "model_loaded": _state["model"] is not None,
            "loaded_at": _state["loaded_at"],
        }

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        """
        Prometheus metrics endpoint. Scraped by the cluster monitoring stack.
        ServiceMonitor CRD in OpenShift/RKE2 configures Prometheus to scrape this.
        """
        return Response(generate_latest(), media_type="text/plain; version=0.0.4")

    # -------------------------------------------------------------------
    # Inference
    # -------------------------------------------------------------------
    class ScoringRequest(BaseModel):
        days_since_last_maintenance: int = Field(..., ge=0, le=3650)
        component_age_years: float = Field(..., ge=0.0, le=50.0)
        operational_hours_30d: int = Field(..., ge=0, le=744)
        deficiency_count_ytd: int = Field(..., ge=0, le=100)
        fy_quarter: int = Field(..., ge=1, le=4)
        requestor_id: str = Field(default="anonymous", max_length=64)

    class ScoringResponse(BaseModel):
        request_id: str
        failure_probability: float
        risk_tier: str
        model_uri: str | None
        scored_at_utc: str
        latency_ms: float

    @app.post("/score", response_model=ScoringResponse)
    async def score(
        request: ScoringRequest,
        req: Request,
        token: str = Security(verify_token),
    ):
        start = time.perf_counter()
        request_id = str(uuid.uuid4())

        input_df = pd.DataFrame([{
            "days_since_last_maintenance": request.days_since_last_maintenance,
            "component_age_years": request.component_age_years,
            "operational_hours_30d": request.operational_hours_30d,
            "deficiency_count_ytd": request.deficiency_count_ytd,
            "fy_quarter": request.fy_quarter,
        }])

        if _state["model"] is not None:
            raw = _state["model"].predict(input_df)
            prob = float(raw[0])
        else:
            prob = 0.42  # demo mode

        risk_tier = "HIGH" if prob >= 0.55 else ("MEDIUM" if prob >= 0.20 else "LOW")
        latency_ms = (time.perf_counter() - start) * 1000

        # Prometheus metrics
        INFERENCE_REQUESTS.labels(status="success", risk_tier=risk_tier).inc()
        INFERENCE_LATENCY.observe(latency_ms / 1000)
        PREDICTION_SCORE.observe(prob)

        # Structured audit log — ingested by SIEM
        audit_record = {
            "event": "model_inference",
            "request_id": request_id,
            "requestor_id": request.requestor_id,
            "client_ip": req.client.host if req.client else "unknown",
            "model_uri": _state["model_uri"],
            "input": input_df.to_dict(orient="records")[0],
            "prediction": round(prob, 4),
            "risk_tier": risk_tier,
            "latency_ms": round(latency_ms, 2),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        print(json.dumps(audit_record))  # structured logging picked up by container runtime

        return ScoringResponse(
            request_id=request_id,
            failure_probability=round(prob, 4),
            risk_tier=risk_tier,
            model_uri=_state["model_uri"],
            scored_at_utc=datetime.now(timezone.utc).isoformat(),
            latency_ms=round(latency_ms, 2),
        )

    return app


# ---------------------------------------------------------------------------
# Section 2: Kubernetes Manifest Generation
# ---------------------------------------------------------------------------
# RKE2 is the DoD-standard Kubernetes distribution (DISA STIG-compliant).
# OpenShift is also common on programs with Red Hat Enterprise Linux mandates.
# Both use the same manifest format with minor differences in SecurityContext
# and route vs ingress configuration.
#
# Writing manifests as Python-generated YAML lets you parameterize them
# for dev/test/prod environments without duplicating files. Most government
# programs use Helm or Kustomize; this pattern shows the underlying manifest
# structure so you understand what Helm is generating.


def generate_deployment_manifest(
    app_name: str,
    image: str,
    namespace: str,
    replicas: int = 2,
    model_uri: str = "",
    api_token_secret: str = "inference-api-token",
    environment: str = "production",
    resource_preset: str = "small",
) -> dict:
    """
    Generate a Kubernetes Deployment manifest for the inference service.

    resource_preset: 'small' (2 replicas, 0.5 CPU / 512Mi each),
                     'medium' (3 replicas, 1 CPU / 1Gi each),
                     'large'  (4 replicas, 2 CPU / 2Gi each)

    The SecurityContext settings here are required by the DISA Kubernetes STIG:
    - runAsNonRoot: true — containers must not run as root (uid 0)
    - readOnlyRootFilesystem: true — prevents runtime filesystem modification
    - allowPrivilegeEscalation: false — prevents sudo/setuid attacks
    - seccompProfile: RuntimeDefault — enables default syscall filtering
    """
    resources = {
        "small": {"requests": {"cpu": "250m", "memory": "256Mi"}, "limits": {"cpu": "500m", "memory": "512Mi"}},
        "medium": {"requests": {"cpu": "500m", "memory": "512Mi"}, "limits": {"cpu": "1000m", "memory": "1Gi"}},
        "large": {"requests": {"cpu": "1000m", "memory": "1Gi"}, "limits": {"cpu": "2000m", "memory": "2Gi"}},
    }[resource_preset]

    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": app_name,
            "namespace": namespace,
            "labels": {
                "app": app_name,
                "environment": environment,
                "version": "stable",  # used for blue-green traffic switching
            },
            "annotations": {
                "kubernetes.io/change-cause": f"Deployed {app_name} to {environment}",
            },
        },
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": app_name, "version": "stable"}},
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {
                    # At most 1 pod unavailable during update (for 2-replica deployment)
                    "maxUnavailable": 1,
                    "maxSurge": 1,
                },
            },
            "template": {
                "metadata": {
                    "labels": {"app": app_name, "version": "stable"},
                    "annotations": {
                        # Prometheus scraping — ServiceMonitor also works but this is simpler
                        "prometheus.io/scrape": "true",
                        "prometheus.io/port": "8080",
                        "prometheus.io/path": "/metrics",
                    },
                },
                "spec": {
                    # Pod-level security: no privilege escalation at the pod level
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 1001,
                        "fsGroup": 1001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": app_name,
                            "image": image,
                            "imagePullPolicy": "Always",
                            "ports": [{"containerPort": 8080, "name": "http"}],
                            "env": [
                                {"name": "ENVIRONMENT", "value": environment},
                                {"name": "MODEL_URI", "value": model_uri},
                                {
                                    "name": "INFERENCE_API_TOKEN",
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": api_token_secret,
                                            "key": "token",
                                        }
                                    },
                                },
                            ],
                            "resources": resources,
                            # Container-level security
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            # Liveness probe: if this fails, pod is restarted
                            "livenessProbe": {
                                "httpGet": {"path": "/health", "port": 8080},
                                "initialDelaySeconds": 10,
                                "periodSeconds": 30,
                                "failureThreshold": 3,
                            },
                            # Readiness probe: if this fails, pod is removed from Service
                            # initialDelaySeconds allows model loading time before traffic arrives
                            "readinessProbe": {
                                "httpGet": {"path": "/readiness", "port": 8080},
                                "initialDelaySeconds": 30,
                                "periodSeconds": 10,
                                "failureThreshold": 3,
                            },
                            # Graceful shutdown: give in-flight requests 30s to complete
                            "lifecycle": {
                                "preStop": {"exec": {"command": ["sleep", "5"]}}
                            },
                            # tmpDir is the only writable path (readOnlyRootFilesystem=true)
                            "volumeMounts": [
                                {"name": "tmp", "mountPath": "/tmp"},
                            ],
                        }
                    ],
                    "volumes": [
                        {"name": "tmp", "emptyDir": {}}
                    ],
                    # Graceful termination period — Kubernetes waits this long after
                    # sending SIGTERM before sending SIGKILL
                    "terminationGracePeriodSeconds": 60,
                },
            },
        },
    }
    return manifest


def generate_service_manifest(app_name: str, namespace: str) -> dict:
    """Generate a Kubernetes Service manifest for internal cluster traffic."""
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": app_name,
            "namespace": namespace,
            "labels": {"app": app_name},
        },
        "spec": {
            "selector": {"app": app_name},  # Routes to any pod with this label
            "ports": [{"port": 80, "targetPort": 8080, "name": "http"}],
            "type": "ClusterIP",  # Internal only — use Ingress/Route for external access
        },
    }


def generate_hpa_manifest(
    app_name: str,
    namespace: str,
    min_replicas: int = 2,
    max_replicas: int = 8,
    cpu_target_pct: int = 70,
) -> dict:
    """
    Generate a HorizontalPodAutoscaler manifest.

    Government workloads have distinct scaling patterns. A DoD analytics
    dashboard used 0800-1700 Mon-Fri doesn't need the same replica count
    at 0300 Saturday. HPA handles this automatically based on CPU load.

    min_replicas=2 ensures availability even when CPU is low.
    Setting min_replicas=1 is almost always wrong for a production service —
    a single pod means any restart (planned or not) causes downtime.
    """
    return {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {"name": f"{app_name}-hpa", "namespace": namespace},
        "spec": {
            "scaleTargetRef": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": app_name,
            },
            "minReplicas": min_replicas,
            "maxReplicas": max_replicas,
            "metrics": [
                {
                    "type": "Resource",
                    "resource": {
                        "name": "cpu",
                        "target": {
                            "type": "Utilization",
                            "averageUtilization": cpu_target_pct,
                        },
                    },
                }
            ],
            # Scale down slowly — don't aggressively remove replicas during
            # the brief lull between briefing sessions. Government dashboards
            # have bursty access patterns.
            "behavior": {
                "scaleDown": {
                    "stabilizationWindowSeconds": 300,  # 5-minute window before scaling down
                    "policies": [{"type": "Pods", "value": 1, "periodSeconds": 120}],
                }
            },
        },
    }


def write_manifests_to_directory(output_dir: str, app_name: str = "maintenance-risk-api"):
    """
    Write complete Kubernetes manifests to a directory structure.
    In practice these would live in a GitOps repository (Flux/ArgoCD).
    """
    import pathlib

    base = pathlib.Path(output_dir)

    for env in ("dev", "staging", "production"):
        env_dir = base / env
        env_dir.mkdir(parents=True, exist_ok=True)

        replicas = {"dev": 1, "staging": 2, "production": 3}[env]
        preset = {"dev": "small", "staging": "small", "production": "medium"}[env]

        # Deployment
        deployment = generate_deployment_manifest(
            app_name=app_name,
            image=f"registry.don.mil/analytics/{app_name}:latest",
            namespace=f"analytics-{env}",
            replicas=replicas,
            model_uri=f"models:/maintenance_risk/{env.capitalize()}",
            environment=env,
            resource_preset=preset,
        )
        with open(env_dir / "deployment.yaml", "w") as f:
            yaml.dump(deployment, f, default_flow_style=False)

        # Service
        service = generate_service_manifest(app_name, f"analytics-{env}")
        with open(env_dir / "service.yaml", "w") as f:
            yaml.dump(service, f, default_flow_style=False)

        # HPA (production only — dev/staging use fixed replica counts)
        if env == "production":
            hpa = generate_hpa_manifest(app_name, "analytics-production")
            with open(env_dir / "hpa.yaml", "w") as f:
                yaml.dump(hpa, f, default_flow_style=False)

    print(f"Manifests written to {output_dir}/")
    print("Directory structure:")
    for p in sorted(base.rglob("*.yaml")):
        print(f"  {p.relative_to(base)}")


# ---------------------------------------------------------------------------
# Section 3: Blue-Green Deployment Logic
# ---------------------------------------------------------------------------
# Blue-green deployment keeps two identical environments running simultaneously.
# "Blue" is the current production version; "green" is the new version.
# Traffic switches from blue to green atomically — no rolling update period
# where some users hit v1 and others hit v2.
#
# In government programs this pattern matters because:
# 1. Your ATO may specify that production changes require approval before
#    any traffic reaches the new version (a rolling update violates this)
# 2. If the new version has a problem, rollback is instant (flip traffic back)
# 3. Some programs require the old version to remain available for a period
#    after the switch for audit/reproducibility purposes
#
# Implementation on Kubernetes: two Deployments with different version labels,
# one Service that selects by version label.


def generate_blue_green_manifests(
    app_name: str,
    namespace: str,
    blue_image: str,
    green_image: str,
    active_color: str = "blue",
) -> dict[str, Any]:
    """
    Generate blue-green deployment manifests.

    The trick: the Service's selector uses `version` label. Switching production
    traffic from blue to green is a single `kubectl patch` on the Service —
    no deployment change needed.

    active_color: which color is currently live ('blue' or 'green')
    """
    inactive_color = "green" if active_color == "blue" else "blue"
    images = {"blue": blue_image, "green": green_image}

    manifests = {}

    for color in ("blue", "green"):
        manifests[f"deployment-{color}"] = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": f"{app_name}-{color}",
                "namespace": namespace,
                "labels": {"app": app_name, "color": color},
            },
            "spec": {
                "replicas": 2,
                "selector": {"matchLabels": {"app": app_name, "color": color}},
                "template": {
                    "metadata": {
                        "labels": {"app": app_name, "color": color},
                    },
                    "spec": {
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 1001,
                        },
                        "containers": [{
                            "name": app_name,
                            "image": images[color],
                            "ports": [{"containerPort": 8080}],
                            "livenessProbe": {
                                "httpGet": {"path": "/health", "port": 8080},
                                "initialDelaySeconds": 10,
                                "periodSeconds": 30,
                            },
                            "readinessProbe": {
                                "httpGet": {"path": "/readiness", "port": 8080},
                                "initialDelaySeconds": 30,
                                "periodSeconds": 10,
                            },
                        }],
                    },
                },
            },
        }

    # Service points to whichever color is active
    manifests["service"] = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": app_name,
            "namespace": namespace,
            "annotations": {
                "deployment-strategy": "blue-green",
                "active-color": active_color,
            },
        },
        "spec": {
            # This selector is all that changes during a blue-green switch
            "selector": {"app": app_name, "color": active_color},
            "ports": [{"port": 80, "targetPort": 8080}],
            "type": "ClusterIP",
        },
    }

    return manifests


def switch_blue_green_traffic(
    app_name: str,
    namespace: str,
    target_color: str,
    dry_run: bool = True,
) -> str:
    """
    Generate the kubectl command to switch production traffic to a new color.

    In practice this runs from a CI/CD pipeline (GitHub Actions, GitLab CI, Tekton)
    after the green deployment has passed smoke tests and the change manager has
    approved the switch.

    dry_run=True: prints the command without executing (safe to run in docs/demos)
    """
    patch = json.dumps({"spec": {"selector": {"app": app_name, "color": target_color}}})

    cmd = (
        f"kubectl patch service {app_name} "
        f"-n {namespace} "
        f"--type=merge "
        f"-p '{patch}'"
    )

    if dry_run:
        print(f"[DRY RUN] Traffic switch command:")
        print(f"  {cmd}")
        print(f"\nThis would route all traffic to the {target_color} deployment.")
        print(f"Rollback: re-run with target_color='{'blue' if target_color == 'green' else 'green'}'")
    else:
        import subprocess
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Traffic switched to {target_color}: {result.stdout}")
        else:
            raise RuntimeError(f"kubectl patch failed: {result.stderr}")

    return cmd


# ---------------------------------------------------------------------------
# Section 4: Canary Deployment with Prometheus-Based Promotion/Rollback
# ---------------------------------------------------------------------------
# Canary deployment sends a small percentage of traffic (5-10%) to the new
# version while the rest goes to stable. If the canary's error rate or latency
# stays within acceptable bounds, the canary is promoted to 100%.
#
# This is more complex than blue-green but lets you catch model regression on
# real production traffic with limited blast radius.
#
# On Kubernetes, canary routing can be done via:
# - Nginx Ingress annotations (weight-based routing)
# - Istio VirtualService (more fine-grained)
# - Argo Rollouts (fully automated canary with metrics-based promotion)
#
# For most government Kubernetes clusters (RKE2, OpenShift without service mesh),
# Nginx Ingress weight-based canary is the most practical option.


def generate_canary_ingress(
    app_name: str,
    namespace: str,
    hostname: str,
    canary_weight_pct: int = 10,
) -> list[dict]:
    """
    Generate Nginx Ingress resources for canary routing.

    This creates two Ingress objects:
    1. The stable ingress (receives (100 - canary_weight_pct)% of traffic)
    2. The canary ingress (receives canary_weight_pct% of traffic)

    Nginx Ingress uses annotation-based canary configuration. The canary
    Ingress's backend points to the canary Service; Nginx splits traffic
    based on the weight annotation.

    Note: OpenShift uses Routes instead of Ingress. The weight annotation
    approach is Nginx-specific; on OpenShift you'd configure this via
    Route alternateBackends.
    """
    stable_ingress = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": f"{app_name}-stable",
            "namespace": namespace,
            "annotations": {
                "nginx.ingress.kubernetes.io/rewrite-target": "/",
            },
        },
        "spec": {
            "rules": [{
                "host": hostname,
                "http": {
                    "paths": [{
                        "path": "/",
                        "pathType": "Prefix",
                        "backend": {
                            "service": {
                                "name": f"{app_name}-stable",
                                "port": {"number": 80},
                            }
                        },
                    }]
                },
            }]
        },
    }

    canary_ingress = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": f"{app_name}-canary",
            "namespace": namespace,
            "annotations": {
                "nginx.ingress.kubernetes.io/canary": "true",
                "nginx.ingress.kubernetes.io/canary-weight": str(canary_weight_pct),
            },
        },
        "spec": {
            "rules": [{
                "host": hostname,
                "http": {
                    "paths": [{
                        "path": "/",
                        "pathType": "Prefix",
                        "backend": {
                            "service": {
                                "name": f"{app_name}-canary",
                                "port": {"number": 80},
                            }
                        },
                    }]
                },
            }]
        },
    }

    return [stable_ingress, canary_ingress]


def evaluate_canary_health(
    prometheus_url: str,
    stable_service: str,
    canary_service: str,
    window_minutes: int = 15,
    max_error_rate_pct: float = 2.0,
    max_p99_latency_ms: float = 500.0,
) -> dict[str, Any]:
    """
    Query Prometheus to evaluate whether the canary deployment is healthy.
    Returns a decision: promote, rollback, or continue monitoring.

    In a real pipeline, this runs every N minutes after canary deploy.
    Argo Rollouts automates this loop; without it, you run this in CI/CD.

    Queries assume the prometheus-client metrics from Section 1 are being scraped.
    """
    try:
        import requests
    except ImportError:
        raise ImportError("pip install requests")

    def query(promql: str) -> float:
        """Execute a PromQL instant query and return the scalar result."""
        resp = requests.get(
            f"{prometheus_url}/api/v1/query",
            params={"query": promql},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data["data"]["result"]:
            return float(data["data"]["result"][0]["value"][1])
        return 0.0

    window = f"{window_minutes}m"

    # Error rate: requests with status != "success" / total requests
    canary_error_rate = query(
        f'100 * rate(inference_requests_total{{service="{canary_service}", status!="success"}}[{window}])'
        f' / rate(inference_requests_total{{service="{canary_service}"}}[{window}])'
    )

    stable_error_rate = query(
        f'100 * rate(inference_requests_total{{service="{stable_service}", status!="success"}}[{window}])'
        f' / rate(inference_requests_total{{service="{stable_service}"}}[{window}])'
    )

    # P99 latency
    canary_p99 = query(
        f'histogram_quantile(0.99, rate(inference_latency_seconds_bucket{{service="{canary_service}"}}[{window}])) * 1000'
    )

    stable_p99 = query(
        f'histogram_quantile(0.99, rate(inference_latency_seconds_bucket{{service="{stable_service}"}}[{window}])) * 1000'
    )

    error_rate_ok = canary_error_rate <= max_error_rate_pct
    latency_ok = canary_p99 <= max_p99_latency_ms
    canary_not_worse_than_stable = (
        canary_error_rate <= stable_error_rate * 1.5  # canary ≤ 150% of stable error rate
    )

    healthy = error_rate_ok and latency_ok and canary_not_worse_than_stable

    result = {
        "canary_error_rate_pct": round(canary_error_rate, 3),
        "stable_error_rate_pct": round(stable_error_rate, 3),
        "canary_p99_ms": round(canary_p99, 1),
        "stable_p99_ms": round(stable_p99, 1),
        "healthy": healthy,
        "decision": "promote" if healthy else "rollback",
        "reason": (
            "All metrics within bounds"
            if healthy
            else (
                f"Error rate {canary_error_rate:.1f}% > {max_error_rate_pct}%"
                if not error_rate_ok
                else f"P99 latency {canary_p99:.0f}ms > {max_p99_latency_ms:.0f}ms"
            )
        ),
    }

    print(f"Canary health check: {result['decision'].upper()}")
    print(f"  Error rate: {canary_error_rate:.2f}% (stable: {stable_error_rate:.2f}%)")
    print(f"  P99 latency: {canary_p99:.0f}ms (stable: {stable_p99:.0f}ms)")
    print(f"  Reason: {result['reason']}")

    return result


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Chapter 11: API Serving & Kubernetes Deployment Demo ===\n")

    # 1. Show FastAPI app creation
    print("--- FastAPI Production App ---")
    app = create_production_app()
    print("App created. Endpoints: /health, /readiness, /metrics, /score")
    print()

    # 2. Generate Kubernetes manifests
    print("--- Kubernetes Manifest Generation ---")
    deployment = generate_deployment_manifest(
        app_name="maintenance-risk-api",
        image="registry.don.mil/analytics/maintenance-risk-api:v1.2.0",
        namespace="analytics-production",
        replicas=3,
        model_uri="models:/maintenance_risk/Production",
        environment="production",
        resource_preset="medium",
    )
    print(f"Deployment manifest: {deployment['metadata']['name']}")
    print(f"  Replicas: {deployment['spec']['replicas']}")
    print(f"  Strategy: {deployment['spec']['strategy']['type']}")
    print(f"  Security: runAsNonRoot={deployment['spec']['template']['spec']['securityContext']['runAsNonRoot']}")
    print()

    # 3. Blue-green manifests
    print("--- Blue-Green Deployment ---")
    bg_manifests = generate_blue_green_manifests(
        app_name="maintenance-risk-api",
        namespace="analytics-production",
        blue_image="registry.don.mil/analytics/maintenance-risk-api:v1.1.0",
        green_image="registry.don.mil/analytics/maintenance-risk-api:v1.2.0",
        active_color="blue",
    )
    print(f"Blue-green manifests created: {list(bg_manifests.keys())}")
    switch_blue_green_traffic(
        "maintenance-risk-api", "analytics-production", "green", dry_run=True
    )
    print()

    # 4. Canary ingress
    print("--- Canary Ingress (10% traffic) ---")
    canary = generate_canary_ingress(
        app_name="maintenance-risk-api",
        namespace="analytics-production",
        hostname="maintenance-risk.don.mil",
        canary_weight_pct=10,
    )
    print(f"Ingress objects: {[i['metadata']['name'] for i in canary]}")
    print(f"Canary weight: {canary[1]['metadata']['annotations']['nginx.ingress.kubernetes.io/canary-weight']}%")
