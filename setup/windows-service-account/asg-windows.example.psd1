# Site settings for the Windows gateway-host scripts. Copy to asg-windows.psd1 next to the scripts and edit.
# Paths and hosts only - never put keys, tokens or passwords here.
@{
    # Profile directory that owns ASG state (~\.agent-security-gateway) and code (~\agent-security-gateway).
    StateHome   = 'C:\Users\<operator>'
    CodeDir     = 'C:\Users\<operator>\agent-security-gateway'
    PythonExe   = 'C:\Program Files\Python312\python.exe'
    AsgPort     = 8788                      # gateway binds 127.0.0.1:<AsgPort>
    # Reverse tunnel to the worker host: exposes 127.0.0.1:<AsgPort> as <TunnelBindIP>:<AsgPort> there.
    WorkerHost  = 'worker-host.example'
    WorkerUser  = 'tunnel'                  # restricted key-only account on the worker host
    TunnelBindIP = '10.90.0.1'              # worker bridge address (default of setup/firecracker-golden)
    GatewayAccount = 'asgsvc'
    TunnelAccount  = 'asgtun'
    GatewayTask = 'AgentSecurityGateway'
    TunnelTask  = 'ASG-Tunnel'
    BackupTag   = 'bak-r19'
}
