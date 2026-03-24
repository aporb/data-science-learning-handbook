#!/usr/bin/env bash
# deploy_containers.sh — Build and push Docker images for the handbook stack.
#
# Builds each Dockerfile in docker/ and optionally pushes to a container registry.
#
# Usage:
#   ./deploy_containers.sh [--push] [--registry <registry>] [--tag <tag>]
#
# Examples:
#   ./deploy_containers.sh                              # build only
#   ./deploy_containers.sh --push --registry ghcr.io/myorg --tag v1.2.0
#
# Dependencies: docker

set -euo pipefail

PUSH=false
REGISTRY=""
TAG="latest"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --push)             PUSH=true ;;
    --registry)         REGISTRY="$2"; shift ;;
    --tag)              TAG="$2"; shift ;;
    *)                  echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKER_DIR="$REPO_ROOT/docker"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found"
docker info >/dev/null 2>&1       || die "Docker daemon not running"

# Map Dockerfile suffix → image name
declare -A IMAGES=(
  [jupyter]="dshb-jupyter"
  [mlflow]="dshb-mlflow"
  [postgres]="dshb-postgres"
  [redis]="dshb-redis"
  [nginx]="dshb-nginx"
  [vault]="dshb-vault"
  [cac-auth]="dshb-cac-auth"
)

build_image() {
  local suffix="$1"
  local name="$2"
  local dockerfile="$DOCKER_DIR/Dockerfile.$suffix"

  if [[ ! -f "$dockerfile" ]]; then
    log "WARNING: $dockerfile not found — skipping $name"
    return
  fi

  local full_name="$name:$TAG"
  if [[ -n "$REGISTRY" ]]; then
    full_name="$REGISTRY/$full_name"
  fi

  log "Building $full_name from $dockerfile ..."
  docker build -f "$dockerfile" -t "$full_name" "$REPO_ROOT"
  log "Built: $full_name"

  if $PUSH; then
    log "Pushing $full_name ..."
    docker push "$full_name"
    log "Pushed: $full_name"
  fi
}

for suffix in "${!IMAGES[@]}"; do
  build_image "$suffix" "${IMAGES[$suffix]}"
done

log "All images processed."
if $PUSH; then
  log "Images pushed to registry: ${REGISTRY:-local}"
else
  log "To push images, rerun with --push --registry <registry>"
fi
