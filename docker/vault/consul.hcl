# Consul Configuration for Vault HA Backend
# Data Science Learning Handbook

datacenter = "dc1"
data_dir = "/consul/data"
log_level = "INFO"
node_name = "consul-node"
server = true
bootstrap_expect = 1

# Bind addresses
bind_addr = "0.0.0.0"
client_addr = "0.0.0.0"

# UI Configuration
ui_config {
  enabled = true
}

# Performance and security settings
performance {
  raft_multiplier = 1
}

# ACL Configuration (for production security)
acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
}

# Connect service mesh (disabled for simplicity)
connect {
  enabled = false
}

# Ports configuration
ports {
  grpc = 8502
  http = 8500
  https = 8501
  dns = 8600
}

# Logging
log_file = "/consul/data/consul.log"
log_rotate_duration = "24h"
log_rotate_max_files = 7

# Raft protocol (for consensus)
raft_protocol = 3

# Disable remote exec for security
disable_remote_exec = true

# TLS Configuration (commented out for initial setup)
# tls {
#   defaults {
#     verify_incoming = true
#     verify_outgoing = true
#     ca_file = "/consul/tls/ca.pem"
#     cert_file = "/consul/tls/consul.pem"
#     key_file = "/consul/tls/consul-key.pem"
#   }
# }

# Autopilot (for automatic dead server cleanup)
autopilot {
  cleanup_dead_servers = true
  last_contact_threshold = "200ms"
  max_trailing_logs = 250
  server_stabilization_time = "10s"
}