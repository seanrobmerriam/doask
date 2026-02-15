# dk

`dk` is a small two-process privilege elevation tool for Unix-like systems (Linux and OpenBSD):

- `dk`: client CLI (`dk <command> [args...]`)
- `dkd`: root daemon that authenticates the caller via SSH challenge/response and executes the requested command as root

It is designed to be a `sudo`-like workflow in a shell session, but with SSH key authentication instead of password prompts.

## Install

Build and install both binaries into your `GOBIN`:

```bash
go install ./cmd/...
```

## Install on OpenBSD

Install Go, build, and place binaries in a root-owned path:

```bash
doas pkg_add go
git clone https://github.com/seanrobmerriam/doask.git
cd doask
go install ./cmd/...
doas install -m 0755 "$(go env GOPATH)/bin/dk" /usr/local/bin/dk
doas install -m 0755 "$(go env GOPATH)/bin/dkd" /usr/local/bin/dkd
```

Create the allowlist file:

```bash
doas mkdir -p /etc/dk
doas touch /etc/dk/authorized_keys
doas chown root:wheel /etc/dk/authorized_keys
doas chmod 600 /etc/dk/authorized_keys
```

Run the daemon as root (example):

```bash
doas /usr/local/bin/dkd -a /etc/dk/authorized_keys -s /var/run/dk.sock
```

## Runtime Layout

```text
dk/
├── go.mod
├── cmd/
│   ├── dk/main.go
│   └── dkd/main.go
├── internal/
│   ├── proto/messages.go
│   └── auth/ssh.go
└── README.md
```

## Start `dkd` as a systemd service

1. Create config and allowlist directory:

```bash
sudo mkdir -p /etc/dk
sudo touch /etc/dk/authorized_keys
sudo chmod 600 /etc/dk/authorized_keys
```

2. Create `/etc/systemd/system/dkd.service`:

```ini
[Unit]
Description=dk privilege daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dkd -a /etc/dk/authorized_keys -s /var/run/dk.sock
Restart=on-failure
RestartSec=2
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

3. Reload and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dkd
sudo systemctl status dkd
```

## Add users to `/etc/dk/authorized_keys`

Add each allowed user’s public key (same format as SSH `authorized_keys`) to `/etc/dk/authorized_keys`.

Example:

```bash
sudo sh -c 'cat /home/alice/.ssh/id_ed25519.pub >> /etc/dk/authorized_keys'
```

Validate file ownership and mode:

```bash
sudo chown root:root /etc/dk/authorized_keys
sudo chmod 600 /etc/dk/authorized_keys
```

## Usage

Client usage:

```bash
dk [-k <private-key>] [-s <socket>] <command> [args...]
```

Examples:

```bash
dk id
dk ls -la /root
dk -k ~/.ssh/id_rsa whoami
dk -s /tmp/dk.sock uname -a
```

Daemon usage:

```bash
dkd [-a <authorized_keys>] [-s <socket>]
```

Defaults:

- socket: `/var/run/dk.sock`
- allowlist: `/etc/dk/authorized_keys`

## Security Considerations

- `dkd` must run as root and executes commands as root when authentication succeeds.
- The socket is intentionally mode `0666` to allow local users to connect; access control is enforced by SSH key verification against `/etc/dk/authorized_keys`.
- The daemon only forwards a constrained environment (`PATH`, `TERM`, `LANG`) and forces `HOME=/root`.
- Authentication uses a random 32-byte nonce with signature verification using the provided public key.
- All authentication attempts are logged to stderr and syslog.

## Known Limitations

- No per-command policy model: any authorized key can execute arbitrary root commands.
- No anti-replay beyond per-connection nonce (no session cache or rate limiting).
- No TTY emulation or PAM integration; behavior is command-stream based over a Unix socket.
- Environment forwarding is intentionally minimal; some programs may behave differently from `sudo`.
- Service management instructions in this README are systemd-specific for Linux; OpenBSD users should run `dkd` with local `rc.d`/`rcctl` conventions.
