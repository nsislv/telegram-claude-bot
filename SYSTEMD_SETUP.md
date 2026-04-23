# Systemd User Service Setup

This guide shows how to run the Claude Code Telegram Bot as a persistent systemd user service.

**⚠️ SECURITY NOTE:** Before setting up the service, ensure your `.env` file has `DEVELOPMENT_MODE=false` and `ENVIRONMENT=production` for secure operation.

## Quick Setup

### 1. Create the service file

```bash
mkdir -p ~/.config/systemd/user
nano ~/.config/systemd/user/claude-telegram-bot.service
```

Add this content:

```ini
[Unit]
Description=Claude Code Telegram Bot
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/ubuntu/Code/oss/claude-code-telegram
ExecStart=/home/ubuntu/.local/bin/poetry run claude-telegram-bot
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Environment
Environment="PATH=/home/ubuntu/.local/bin:/usr/local/bin:/usr/bin:/bin"

# --- Hardening ----------------------------------------------------
# Every line below shrinks the blast radius if the bot process (or
# Claude, via a tool call) is compromised. Adjust ReadWritePaths to
# match your APPROVED_DIRECTORY.

# Privilege / credentials
NoNewPrivileges=yes
RestrictSUIDSGID=yes

# Filesystem isolation
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/home/ubuntu/Code/oss/claude-code-telegram /home/ubuntu/projects
PrivateTmp=yes
PrivateDevices=yes

# Kernel surface
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid

# Process hardening
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RemoveIPC=yes

# Network surface — IPv4/6 + local unix sockets only
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Capabilities — drop everything. The bot only needs outbound TCP.
CapabilityBoundingSet=
AmbientCapabilities=

# Syscall filter — standard service profile, deny the dangerous classes.
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @obsolete
SystemCallErrorNumber=EPERM

# Resource ceilings (tune for your host)
LimitNOFILE=4096
TasksMax=256
# ------------------------------------------------------------------

[Install]
WantedBy=default.target
```

**Note:** Update `WorkingDirectory` and `ReadWritePaths` to your
project path and your `APPROVED_DIRECTORY`. If the bot cannot start
after adding the hardening block, bisect by commenting out one
directive at a time (`MemoryDenyWriteExecute=yes` and the
`SystemCallFilter` lines are the two most common culprits when
native extensions are in use).

### 2. Enable and start the service

```bash
# Reload systemd to recognize the new service
systemctl --user daemon-reload

# Enable auto-start on login
systemctl --user enable claude-telegram-bot.service

# Start the service now
systemctl --user start claude-telegram-bot.service
```

### 3. Verify it's running

```bash
systemctl --user status claude-telegram-bot
```

### 4. Verify secure configuration

Check that the service is running in production mode:

```bash
# Check logs for environment mode
journalctl --user -u claude-telegram-bot -n 50 | grep -i "environment\|development"

# Should show:
# "environment": "production"
# "development_mode": false (implied, not shown if false)

# Verify authentication is restricted
journalctl --user -u claude-telegram-bot -n 50 | grep -i "auth"

# Should show:
# "allowed_users": 1 (or more if multiple users configured)
# "allow_all_dev": false
```

If you see `allow_all_dev: true` or `environment: development`, **STOP THE SERVICE** and fix your `.env` file immediately.

## Common Commands

```bash
# Start service
systemctl --user start claude-telegram-bot

# Stop service
systemctl --user stop claude-telegram-bot

# Restart service
systemctl --user restart claude-telegram-bot

# View status
systemctl --user status claude-telegram-bot

# View live logs
journalctl --user -u claude-telegram-bot -f

# View recent logs (last 50 lines)
journalctl --user -u claude-telegram-bot -n 50

# Disable auto-start
systemctl --user disable claude-telegram-bot

# Enable auto-start
systemctl --user enable claude-telegram-bot
```

## Updating the Service

After editing the service file:

```bash
systemctl --user daemon-reload
systemctl --user restart claude-telegram-bot
```

## Troubleshooting

**Service won't start:**
```bash
# Check logs for errors
journalctl --user -u claude-telegram-bot -n 100

# Verify paths in service file are correct
systemctl --user cat claude-telegram-bot

# Check that Poetry is installed
poetry --version

# Test the bot manually first
cd /home/ubuntu/Code/oss/claude-code-telegram
poetry run claude-telegram-bot
```

**Service stops after logout:**

Enable lingering to keep user services running after logout:
```bash
loginctl enable-linger $USER
```

## Files

- Service file: `~/.config/systemd/user/claude-telegram-bot.service`
- Logs: View with `journalctl --user -u claude-telegram-bot`
- Project: `/home/ubuntu/Code/oss/claude-code-telegram`
