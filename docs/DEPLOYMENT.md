# Running Bastion always on

`bastion daemon` is the always-on part: it answers you on Telegram and runs scheduled tasks.
It only makes outbound connections (Telegram long polling, your model provider, Google, the
search API), so no port ever needs opening, on any of the setups below.

| Where | Secrets kept in | Guide |
|---|---|---|
| A server, VPS or Raspberry Pi, with Docker | A sealed file, unlocked by a master key | [Docker](#docker-recommended-for-servers) |
| A Linux server without Docker | A sealed file, unlocked by a master key | [systemd](#linux-server-without-docker-systemd) |
| Your own Windows PC | The Windows Credential Manager | [Windows](#windows-run-at-sign-in) |
| Your own Mac | The macOS Keychain | [macOS](#macos-launchd) |

Desktops keep secrets in the OS keyring, which only works inside your signed-in session, so
there Bastion runs as you while you are signed in. Servers have no keyring: there, set
`BASTION_SECRET_STORE=file` and Bastion keeps every secret in `secrets.db`, sealed with AES-GCM
under a 32-byte **master key** that you keep outside Bastion's data folder. A copy of the data
folder (a backup, a stolen disk) then reveals no secret without the key. The
[threat model](THREAT_MODEL.md) says what this does and does not protect.

## Docker (recommended for servers)

The image runs as an unprivileged user, with a read-only root filesystem, every Linux
capability dropped and `no-new-privileges`, all set in [`compose.yaml`](../compose.yaml). It is
built for `amd64` and `arm64` (a Raspberry Pi 4 or 5 runs it fine).

1. Get `compose.yaml` (clone the repository, or download just that file), and verify the image
   you are about to run (see [SECURITY.md](../SECURITY.md#verifying-a-release)).
2. Create the master key next to `compose.yaml`, readable only by the container's user:

   ```sh
   (umask 077 && head -c 32 /dev/urandom | base64 > bastion_master_key)
   sudo chown 10001:10001 bastion_master_key
   ```

   (Or, on any machine with Bastion installed: `bastion secrets master-key <file>`, then the
   same `chown`.) Rootless Docker and Podman map user ids differently: there, make the key
   readable by the user the container's uid 10001 maps to.
   **Back the key up somewhere other than the data volume.** Without it, the secrets sealed
   with it are gone and Bastion has to be set up again.
3. Set up, interactively (each step stores its secrets in the sealed file):

   ```sh
   docker compose run --rm bastion init
   docker compose run --rm bastion telegram setup
   docker compose run --rm bastion telegram pair
   docker compose run --rm bastion telegram totp
   docker compose run --rm bastion google connect --no-browser   # optional
   ```

   `--no-browser` prints a sign-in link to open on any device. After you sign in, your browser
   fails to load a page starting with `http://127.0.0.1:8765/`: that is expected. Copy that
   whole address and paste it back into the terminal. It only completes this sign-in, from
   this machine. (A model served by Ollama on the host is not `localhost` from inside the
   container: point `base_url` at the host's address instead.)
4. Start it: `docker compose up -d`. Logs: `docker compose logs -f bastion`.

Day to day:

| Task | Command |
|---|---|
| Emergency stop from your phone | `/stop` on Telegram |
| Release the stop | `docker compose run --rm bastion resume` |
| Run the red-team suite inside the container | `docker compose run --rm bastion redteam` |
| Check the audit log | `docker compose run --rm bastion audit verify` |
| Update | `docker compose pull && docker compose up -d` (verify the new image first) |
| Back up | Copy the `bastion-data` volume; keep the master key somewhere else |

## Linux server without Docker (systemd)

```sh
sudo useradd --system --create-home --home-dir /var/lib/bastion --shell /usr/sbin/nologin bastion
sudo -u bastion -H bash -c 'cd ~ && git clone https://github.com/AryanVault/bastion.git app \
  && cd app && uv sync --locked --no-dev'
sudo install -d -m 0750 -o root -g bastion /etc/bastion
(umask 077 && head -c 32 /dev/urandom | base64 | sudo tee /etc/bastion/master.key >/dev/null)
sudo chown root:bastion /etc/bastion/master.key && sudo chmod 0440 /etc/bastion/master.key
```

Set up as that user, with the same environment the service will have:

```sh
bastion() {
  sudo -u bastion BASTION_HOME=/var/lib/bastion/data BASTION_SECRET_STORE=file \
    BASTION_MASTER_KEY_FILE=/etc/bastion/master.key /var/lib/bastion/app/.venv/bin/bastion "$@"
}
bastion init && bastion telegram setup && bastion telegram pair && bastion telegram totp
bastion google connect --no-browser   # optional
```

(`uv` must be on the `bastion` user's `PATH` for the `uv sync` above; `bastion init` creates
`/var/lib/bastion/data`, which the unit below needs to exist.)

Then add `/etc/systemd/system/bastion.service`:

```ini
[Unit]
Description=Bastion personal agent
After=network-online.target
Wants=network-online.target

[Service]
User=bastion
Group=bastion
Environment=BASTION_HOME=/var/lib/bastion/data
Environment=BASTION_SECRET_STORE=file
Environment=BASTION_MASTER_KEY_FILE=/etc/bastion/master.key
ExecStart=/var/lib/bastion/app/.venv/bin/bastion daemon
Restart=on-failure
RestartSec=10
UMask=0077
# Hardening: the service can write only its own data folder.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/bastion/data
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

`sudo systemctl daemon-reload && sudo systemctl enable --now bastion`; logs with
`journalctl -u bastion -f`. `systemctl stop` sends SIGTERM, which Bastion handles like Ctrl+C:
it finishes cleanly and checkpoints the audit log.

## Windows (run at sign-in)

Set Bastion up once in a terminal as yourself (`uv run bastion init`, `telegram setup`,
`telegram pair`, `telegram totp`, `google connect`), then, from the checkout, create a
scheduled task that starts the daemon when you sign in:

```powershell
$bastion  = (Resolve-Path .\.venv\Scripts\bastion.exe).Path
$action   = New-ScheduledTaskAction -Execute $bastion -Argument "daemon"
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
  -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "Bastion" -Action $action -Trigger $trigger -Settings $settings
```

It runs as you (the Credential Manager is per user), only while you are signed in. Stop it
with `Stop-ScheduledTask Bastion`, remove it with `Unregister-ScheduledTask Bastion`. For a PC
that must answer while nobody is signed in, use Docker or WSL with the sealed file store.

## macOS (launchd)

After setting up in a terminal, save as `~/Library/LaunchAgents/dev.bastion.daemon.plist`,
with the path to your checkout:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.bastion.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/bastion/.venv/bin/bastion</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardErrorPath</key><string>/Users/YOU/Library/Logs/bastion.log</string>
</dict>
</plist>
```

`launchctl load ~/Library/LaunchAgents/dev.bastion.daemon.plist` starts it now and at every
sign-in. A LaunchAgent runs in your session, so it can read your Keychain.

## Whatever the setup

- Run **one** daemon per Telegram bot: two would compete for its updates.
- `/stop` on Telegram stops all work, and only the machine can release it (`bastion resume`):
  keep a way to reach the machine.
- `bastion audit verify --checkpoint <entry>:<chain>` checks the log against a checkpoint the
  bot sent you.
