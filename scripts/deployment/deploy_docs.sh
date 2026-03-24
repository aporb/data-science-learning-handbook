#!/usr/bin/env bash
# deploy_docs.sh — Build and deploy the handbook documentation site.
#
# Supports two deployment targets:
#   local   — Serve on localhost:8000 for preview
#   github  — Push built site to gh-pages branch (requires write access)
#
# Usage:
#   ./deploy_docs.sh [local|github] [--dry-run]
#
# Dependencies: python3, pip (mkdocs or sphinx), git

set -euo pipefail

TARGET="${1:-local}"
DRY_RUN=false
if [[ "${2:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCS_DIR="$REPO_ROOT/docs"
BUILD_DIR="$REPO_ROOT/_site"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

# ── Prerequisite checks ────────────────────────────────────────────────────────

command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v git >/dev/null 2>&1    || die "git not found"

cd "$REPO_ROOT"

# ── Build step ─────────────────────────────────────────────────────────────────

build_docs() {
  log "Building documentation..."
  if command -v mkdocs >/dev/null 2>&1; then
    log "Using mkdocs"
    if $DRY_RUN; then
      log "[dry-run] mkdocs build --site-dir $BUILD_DIR"
    else
      mkdocs build --site-dir "$BUILD_DIR"
    fi
  else
    log "mkdocs not found — generating minimal HTML index from docs/index.html"
    mkdir -p "$BUILD_DIR"
    if $DRY_RUN; then
      log "[dry-run] Would copy $DOCS_DIR → $BUILD_DIR"
    else
      cp -r "$DOCS_DIR"/. "$BUILD_DIR/"
      log "Docs copied to $BUILD_DIR"
    fi
  fi
}

# ── Deploy targets ─────────────────────────────────────────────────────────────

deploy_local() {
  log "Starting local preview server at http://localhost:8000 ..."
  if command -v mkdocs >/dev/null 2>&1; then
    mkdocs serve
  else
    python3 -m http.server 8000 --directory "$BUILD_DIR"
  fi
}

deploy_github() {
  [[ -d "$BUILD_DIR" ]] || die "Build directory $BUILD_DIR not found. Run build first."
  log "Deploying to gh-pages branch..."
  if $DRY_RUN; then
    log "[dry-run] Would force-push $BUILD_DIR to gh-pages"
    return
  fi

  # Use git worktree for clean gh-pages deployment
  GH_PAGES_WORKTREE="$REPO_ROOT/.gh-pages-deploy"
  if git worktree list | grep -q "$GH_PAGES_WORKTREE"; then
    git worktree remove --force "$GH_PAGES_WORKTREE" 2>/dev/null || true
  fi

  if git show-ref --quiet refs/heads/gh-pages; then
    git worktree add "$GH_PAGES_WORKTREE" gh-pages
  else
    log "Creating gh-pages branch..."
    git worktree add --orphan -b gh-pages "$GH_PAGES_WORKTREE"
  fi

  rsync -av --delete --exclude='.git' "$BUILD_DIR/" "$GH_PAGES_WORKTREE/"
  cd "$GH_PAGES_WORKTREE"
  git add -A
  git commit -m "docs: deploy handbook site $(date -u '+%Y-%m-%dT%H:%M:%SZ')" || log "Nothing to commit"
  git push origin gh-pages
  cd "$REPO_ROOT"
  git worktree remove --force "$GH_PAGES_WORKTREE"
  log "Deployment complete."
}

# ── Main ───────────────────────────────────────────────────────────────────────

build_docs

case "$TARGET" in
  local)  deploy_local ;;
  github) deploy_github ;;
  *)      die "Unknown target '$TARGET'. Use 'local' or 'github'." ;;
esac
