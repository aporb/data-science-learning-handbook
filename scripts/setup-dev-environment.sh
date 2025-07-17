#!/bin/bash

# Data Science Learning Handbook - Development Environment Setup Script
# This script sets up the complete development environment for the project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check Docker
    if ! command_exists docker; then
        error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command_exists docker-compose; then
        error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check Git
    if ! command_exists git; then
        error "Git is not installed. Please install Git first."
        exit 1
    fi
    
    log "All requirements satisfied ✓"
}

# Create environment files
setup_environment() {
    log "Setting up environment files..."
    
    # Create .env file if it doesn't exist
    if [ ! -f .env ]; then
        cp .env.example .env
        log "Created .env file from template"
    else
        warn ".env file already exists, skipping creation"
    fi
    
    # Create .env.local for local overrides
    if [ ! -f .env.local ]; then
        touch .env.local
        log "Created .env.local file"
    fi
    
    # Set proper permissions
    chmod 600 .env .env.local
}

# Setup directories
setup_directories() {
    log "Setting up directories..."
    
    # Create necessary directories
    mkdir -p logs
    mkdir -p reports/{security,performance,validation}
    mkdir -p data/{raw,processed,models,artifacts}
    mkdir -p notebooks/{exploratory,production,experiments}
    mkdir -p tmp
    
    # Set permissions
    chmod 755 logs reports data notebooks tmp
}

# Install pre-commit hooks
setup_git_hooks() {
    log "Setting up Git hooks..."
    
    if [ -f .pre-commit-config.yaml ]; then
        if command_exists pre-commit; then
            pre-commit install
            log "Pre-commit hooks installed ✓"
        else
            warn "pre-commit not found, skipping hook installation"
        fi
    fi
}

# Setup Python environment
setup_python_env() {
    log "Setting up Python environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log "Created Python virtual environment"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install development dependencies
    if [ -f "requirements-dev.txt" ]; then
        pip install -r requirements-dev.txt
    else
        pip install -r requirements.txt
    fi
    
    log "Python environment setup complete ✓"
}

# Setup Docker environment
setup_docker() {
    log "Setting up Docker environment..."
    
    # Create Docker network if it doesn't exist
    docker network create ds-handbook 2>/dev/null || true
    
    # Build images
    log "Building Docker images..."
    docker-compose build
    
    log "Docker environment setup complete ✓"
}

# Initialize databases
init_databases() {
    log "Initializing databases..."
    
    # Start PostgreSQL
    docker-compose up -d postgres
    
    # Wait for PostgreSQL to be ready
    log "Waiting for PostgreSQL to be ready..."
    sleep 10
    
    # Create MLflow database
    docker-compose exec postgres createdb -U mlflow mlflow || true
    
    log "Database initialization complete ✓"
}

# Setup monitoring
setup_monitoring() {
    log "Setting up monitoring..."
    
    # Start monitoring services
    docker-compose up -d prometheus grafana
    
    log "Monitoring services started ✓"
}

# Run security scan
run_security_scan() {
    log "Running initial security scan..."
    
    # Make security scanner executable
    chmod +x scripts/security/security-scanner.sh
    
    # Run security scan
    ./scripts/security/security-scanner.sh || warn "Security scan failed, continuing..."
}

# Generate documentation
generate_docs() {
    log "Generating documentation..."
    
    # Create documentation index
    cat > docs/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Data Science Learning Handbook</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .link { display: block; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Data Science Learning Handbook</h1>
        <p>Comprehensive guide for data science across multiple platforms</p>
    </div>
    
    <div class="section">
        <h2>Quick Start</h2>
        <a href="http://localhost:8888" class="link">Jupyter Lab</a>
        <a href="http://localhost:5000" class="link">MLflow</a>
        <a href="http://localhost:3000" class="link">Grafana</a>
        <a href="http://localhost:9090" class="link">Prometheus</a>
    </div>
    
    <div class="section">
        <h2>Documentation</h2>
        <a href="http://localhost:8080" class="link">Project Documentation</a>
    </div>
</body>
</html>
EOF
    
    log "Documentation generated ✓"
}

# Main setup function
main() {
    log "Starting Data Science Learning Handbook setup..."
    
    check_requirements
    setup_environment
    setup_directories
    setup_git_hooks
    setup_python_env
    setup_docker
    init_databases
    setup_monitoring
    run_security_scan
    generate_docs
    
    log "Setup complete! 🎉"
    log ""
    log "Services available at:"
    log "  Jupyter Lab: http://localhost:8888"
    log "  MLflow: http://localhost:5000"
    log "  Grafana: http://localhost:3000 (admin/admin)"
    log "  Prometheus: http://localhost:9090"
    log "  Documentation: http://localhost:8080"
    log ""
    log "To start all services: docker-compose up -d"
    log "To stop all services: docker-compose down"
    log "To view logs: docker-compose logs -f"
}

# Handle script arguments
case "$1" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --skip-docker  Skip Docker setup"
        echo "  --skip-python  Skip Python environment setup"
        echo "  --quick        Quick setup (skip optional steps)"
        exit 0
        ;;
    --skip-docker)
        SKIP_DOCKER=true
        ;;
    --skip-python)
        SKIP_PYTHON=true
        ;;
    --quick)
        QUICK_SETUP=true
        ;;
esac

# Run main function
main
