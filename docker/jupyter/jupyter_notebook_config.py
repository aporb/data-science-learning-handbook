# Jupyter Notebook Configuration for Data Science Learning Handbook

c = get_config()

# Server settings
c.ServerApp.ip = '0.0.0.0'
c.ServerApp.port = 8888
c.ServerApp.open_browser = False
c.ServerApp.allow_root = True

# Security settings
c.ServerApp.token = ''
c.ServerApp.password = ''
c.ServerApp.allow_origin = '*'
c.ServerApp.disable_check_xsrf = True

# File and directory settings
c.ServerApp.root_dir = '/workspace'
c.ServerApp.preferred_dir = '/workspace'

# Kernel settings
c.KernelManager.autorestart = True
c.KernelManager.shutdown_wait_time = 10.0

# Extension settings
c.ServerApp.jpserver_extensions = {
    'jupyterlab': True,
    'jupyter_server_proxy': True,
}

# Logging
c.Application.log_level = 'INFO'
c.ServerApp.log_level = 'INFO'

# Resource limits
c.MappingKernelManager.cull_idle_timeout = 3600  # 1 hour
c.MappingKernelManager.cull_interval = 300       # 5 minutes
c.MappingKernelManager.cull_connected = True
c.MappingKernelManager.cull_busy = False

# Enable extensions
c.NotebookApp.nbserver_extensions = {
    'jupyter_nbextensions_configurator': True,
}

# Custom settings for data science
c.FileContentsManager.delete_to_trash = False
c.ContentsManager.allow_hidden = True

# Enable collaboration
c.LabApp.collaborative = True

# Terminal settings
c.ServerApp.terminals_enabled = True
c.NotebookApp.terminals_enabled = True
