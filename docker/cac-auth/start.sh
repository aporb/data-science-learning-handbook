#!/bin/bash

# CAC/PIV Authentication Service Startup Script

set -e

echo "Starting CAC/PIV Authentication Service..."

# Wait for dependencies (if any)
if [ -n "$WAIT_FOR_DEPS" ]; then
    echo "Waiting for dependencies..."
    sleep 10
fi

# Start PCSC daemon if needed (for smart card support)
if [ "$ENABLE_SMART_CARD" = "true" ]; then
    echo "Starting PCSC daemon for smart card support..."
    sudo pcscd --foreground --debug --apdu &
    sleep 2
fi

# Set up environment variables
export PYTHONPATH="/app:$PYTHONPATH"
export CAC_CONFIG_DIR="${CAC_CONFIG_DIR:-/app/config}"
export CAC_LOG_LEVEL="${CAC_LOG_LEVEL:-INFO}"
export CAC_API_HOST="${CAC_API_HOST:-0.0.0.0}"
export CAC_API_PORT="${CAC_API_PORT:-8000}"

# Create necessary directories
mkdir -p /app/logs
mkdir -p /app/config/platforms
mkdir -p /app/config/environments

# Generate default configuration if not exists
if [ ! -f "/app/config/global_config.yaml" ]; then
    echo "Generating default configuration..."
    python3 -c "
from auth.platform_config_manager import PlatformConfigManager
config_manager = PlatformConfigManager('/app/config')
config_manager.create_default_configs()
config_manager.save_configurations()
print('Default configuration created')
"
fi

# Run database migrations (if using database for audit logs)
if [ "$USE_DATABASE" = "true" ]; then
    echo "Running database migrations..."
    # Add database migration commands here
fi

# Start the application
echo "Starting CAC/PIV Authentication API on ${CAC_API_HOST}:${CAC_API_PORT}"

exec python3 -m uvicorn auth.api.auth_api:app \
    --host "${CAC_API_HOST}" \
    --port "${CAC_API_PORT}" \
    --log-level "${CAC_LOG_LEVEL,,}" \
    --access-log \
    --reload-dir /app/auth \
    ${CAC_RELOAD:+--reload}