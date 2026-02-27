# HTTPShell.py

HTTPShell.py is a single‑file remote shell that works entirely over HTTP or HTTPS. It is designed for environments where direct inbound TCP or UDP access is blocked, an example like GCNAT/NAT, but HTTP or HTTPS access is allowed.

It acts as both client and server, and works over standard web infrastructure outbound connections.

---

## Problem

Many networks (ie: GCNAT) block inbound connections. This makes SSH or other remote shell protocols unusable. And cloudflare has it on a paywall.

HTTPShell solves this by using an interactive shell over HTTP or HTTPS using standard web ports and proxy‑compatible traffic.

---

## Requirements

- uv from Astral: https://astral.sh/uv
- Linux system (server side)
- PAM authentication enabled on the server

No additional dependencies are required. uv will handle everything automatically.

---

## Installation

Grab uv from Astral:
```
# Linux
wget -qO- https://astral.sh/uv/install.sh | sh

# Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Now download the single file from Releases:
```
# Linux
sudo wget https://github.com/lspm-pkg/HTTPshell.py/releases/download/v1.0.1/HTTPshell.py -O /usr/bin/httpshell.py

# Windows
curl.exe -LO https://github.com/lspm-pkg/HTTPshell.py/releases/download/v1.0.1/HTTPshell.py
```

Make it executeable using `chmod +x /usr/bin/httpshell.py` on linux.

---

## Usage

### Connect to a server using the client.

```
# Linux
httpshell.py username server-ip

# Windows
uv run httpshell.py username server-ip
```

You will be prompted for the user's password.

---

### Start the server

```
sudo httpshell.py --server
```

This will setup caddy and the backend server.

Install server on startup using `--server-install`.

---

## Features

- Single file for client and server
- Works over HTTP or HTTPS
- Fully interactive shell
- Supports bash, sh, zsh and others
- Supports vim, nano, htop, top and other terminal applications
- PTY based terminal for proper TTY behavior
- PAM authentication using system users
- Reverse proxy support, supports cloudflared out of the box
- Works behind firewalls and restricted networks
- Very Easy to use

---

## Contributing

Pull requests and improvements are welcome.

Security reviews are especially appreciated.
