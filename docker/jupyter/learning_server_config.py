# Jupyter server configuration for the minimal learning lab.
# Public or synthetic data only. This file does not disable authentication.
c = get_config()

c.ServerApp.ip = "0.0.0.0"  # Container interface only. The host port binds to 127.0.0.1.
c.ServerApp.port = 8888
c.ServerApp.open_browser = False
c.ServerApp.allow_root = False
c.ServerApp.allow_origin = ""
c.ServerApp.disable_check_xsrf = False
# Do not set ServerApp.token here. An explicit empty string disables authentication.
# Leaving the default makes Jupyter generate a random token at startup.

c.ServerApp.root_dir = "/home/learner/work"
c.ServerApp.preferred_dir = "/home/learner/work/notebooks"

c.MappingKernelManager.cull_idle_timeout = 3600
c.MappingKernelManager.cull_interval = 300
c.MappingKernelManager.cull_connected = True
c.MappingKernelManager.cull_busy = False

c.FileContentsManager.delete_to_trash = False
c.ServerApp.terminals_enabled = True
c.Application.log_level = "INFO"
