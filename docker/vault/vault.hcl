# HashiCorp Vault Configuration
# High-Availability Configuration for Data Science Learning Handbook

# Storage backend - Consul for HA
storage "consul" {
  address = "consul:8500"
  path    = "vault/"
  ha_enabled = "true"
}

# HA Configuration
ha_storage "consul" {
  address = "consul:8500"
  path    = "vault/"
  cluster_addr = "https://vault:8201"
  redirect_addr = "https://vault:8200"
}

# API listener
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/vault.crt"
  tls_key_file  = "/vault/tls/vault.key"
  tls_min_version = "tls12"
  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
  tls_prefer_server_cipher_suites = "true"
}

# Cluster listener for HA
listener "tcp" {
  address         = "0.0.0.0:8201"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/vault/tls/vault.crt"
  tls_key_file    = "/vault/tls/vault.key"
  tls_min_version = "tls12"
}

# Disable mlock for containerized environments
disable_mlock = true

# Enable UI
ui = true

# Seal configuration - Auto-unseal with cloud provider
# seal "awskms" {
#   region     = "us-gov-west-1"
#   kms_key_id = "alias/vault-unseal-key"
# }

# Default lease settings
default_lease_ttl = "768h"
max_lease_ttl = "8760h"

# Performance settings
cluster_name = "data-science-vault-cluster"
cache_size = "32000"

# Security headers
raw_storage_endpoint = false
disable_clustering = false

# Logging
log_level = "Info"
log_format = "json"
log_file = "/vault/logs/vault.log"
log_rotate_duration = "24h"
log_rotate_max_files = 7

# DoD Security Controls
disable_sealwrap = false
disable_indexing = false
disable_performance_standby = false

# Telemetry for monitoring
telemetry {
  prometheus_retention_time = "24h"
  disable_hostname = false
  enable_hostname_label = true
}

# Plugin directory
plugin_directory = "/vault/plugins"

# API timeout
api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"