#!/bin/bash

# Data Science Learning Handbook - Development Environment Setup
# This script sets up the complete development environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check if running on macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
else
    error "Unsupported operating system: $OSTYPE"
    exit 1
fi

log "Setting up Data Science Learning Handbook development environment on $OS..."

# Check for required tools
check_command() {
    if ! command -v "$1" &> /dev/null; then
        error "$1 is required but not installed. Please install it first."
        exit 1
    fi
}

log "Checking required tools..."
check_command git
check_command docker
check_command docker-compose

# Check for Python
if ! command -v python3 &> /dev/null; then
    error "Python 3 is required but not installed. Please install Python 3.8+."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
log "Python version: $PYTHON_VERSION"

# Create virtual environment
log "Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
log "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
log "Installing Python dependencies..."
pip install -r requirements.txt

# Check for conda
if command -v conda &> /dev/null; then
    log "Conda detected. Creating conda environment..."
    conda env create -f environment.yml --force
    log "Conda environment 'ds-handbook' created. Activate with: conda activate ds-handbook"
else
    warning "Conda not found. Skipping conda environment setup."
fi

# Create necessary directories
log "Creating necessary directories..."
mkdir -p data/{raw,processed,external}
mkdir -p models/{saved_models,checkpoints,experiments}
mkdir -p logs
mkdir -p notebooks/{exploratory,experiments,demos}
mkdir -p reports/{figures,tables}

# Set up pre-commit hooks
log "Setting up pre-commit hooks..."
if [ -f ".pre-commit-config.yaml" ]; then
    pip install pre-commit
    pre-commit install
    log "Pre-commit hooks installed."
else
    warning "No .pre-commit-config.yaml found. Skipping pre-commit setup."
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    log "Creating .env file..."
    cat > .env << EOF
# Development Environment Variables
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=DEBUG

# Database
DATABASE_URL=postgresql://ds_user:ds_password@localhost:5432/ds_handbook
REDIS_URL=redis://localhost:6379/0

# Jupyter
JUPYTER_TOKEN=ds-handbook-2024
JUPYTER_PORT=8888

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here

# Platform APIs
DATABRICKS_HOST=https://your-databricks-instance.cloud.databricks.com
DATABRICKS_TOKEN=your-databricks-token
QLIK_HOST=https://your-qlik-instance.com
QLIK_TOKEN=your-qlik-token
ADVANA_API_KEY=your-advana-api-key
NAVY_JUPITER_API_KEY=your-navy-jupiter-api-key

# Monitoring
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
EOF
    warning "Created .env file. Please update with your actual credentials."
fi

# Build Docker containers
log "Building Docker containers..."
docker-compose build

# Start services
log "Starting Docker services..."
docker-compose up -d postgres redis

# Wait for services to be ready
log "Waiting for services to be ready..."
sleep 10

# Initialize database
log "Initializing database..."
if [ -f "docker/postgres/init.sql" ]; then
    docker-compose exec postgres psql -U ds_user -d ds_handbook -f /docker-entrypoint-initdb.d/init.sql
fi

# Run security scan
log "Running security scan..."
if [ -f "scripts/security-scan.sh" ]; then
    chmod +x scripts/security-scan.sh
    ./scripts/security-scan.sh
else
    warning "Security scan script not found. Skipping security scan."
fi

# Run tests
log "Running tests..."
if [ -d "tests" ]; then
    pytest tests/ -v
else
    warning "No tests directory found. Skipping tests."
fi

# Generate documentation
log "Generating documentation..."
if [ -f "docs/generate-docs.sh" ]; then
    chmod +x docs/generate-docs.sh
    ./docs/generate-docs.sh
else
    warning "Documentation generation script not found."
fi

# Final setup
log "Finalizing setup..."
echo ""
echo "============================================"
echo "🎉 Development environment setup complete!"
echo "============================================"
echo ""
echo "To get started:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Start services: docker-compose up"
echo "3. Access Jupyter: http://localhost:8888 (token: ds-handbook-2024)"
echo "4. Access Grafana: http://localhost:3000 (admin/admin)"
echo "5. Access Prometheus: http://localhost:9090"
echo ""
echo "For platform-specific setup:"
echo "- Update .env with your platform credentials"
echo "- Check platform-guides/ for specific instructions"
echo ""
echo "Happy coding! 🚀"
