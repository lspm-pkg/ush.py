# ush.py (Unsecure Shell)
![Bandwidth](https://img.shields.io/badge/Bandwidth-Ultra--Low-brightgreen)
![Payload](https://img.shields.io/badge/Payload-Keystroke--Level-blue)
![Security](https://img.shields.io/badge/No-Security-red)
![Madeinpy](https://img.shields.io/badge/Made_in-Python-yellow)
![Yaris](https://img.shields.io/badge/Size-9.0_KB-orange)


`ush.py` is an fork of HTTPshell.py. It is a single-file, dependency-minimal remote shell that operates entirely over Websocket. It is specifically optimized for extremely resource-constrained environments (like 32MB RAM) and networks where inbound TCP access is restricted by GCNAT or aggressive firewalls.

By leveraging a PTY-based approach and smart backpressure management, `ush.py` provides a full interactive terminal experience over standard web traffic.

> [!IMPORTANT]
> ush.py IS EXTREMELY UNSECURE. Traffic is sent in plain text. If there is a sniffer or a Man-In-The-Middle (MITM) on the network, your credentials and session data will be stolen.
>
> If you require built-in encryption or even more security, use [HTTPshell.py](https://github.com/lspm-pkg/HTTPshell.py) instead. ush.py should only be used over trusted local networks or behind a secure HTTPS reverse proxy (like Caddy or Cloudflare).
>
> ush.py comes with ABSOLUTELY NO WARRANTY, to the extent permitted by applicable law.

---

## The Problem

Many networks (ie: GCNAT) block inbound connections. This makes SSH or other remote shell protocols unusable. And cloudflare has it on a paywall.

`ush.py` solves this by multiplexing a full TTY session over standard Websocket, making it compatible with almost any reverse proxy (Cloudflare, Caddy, Nginx) and bypassing inbound port restrictions.

---

## Requirements

* **Python 3.8+**

The server side only supports Linux.
The client side supports absolutely anything.

---

## Installation

Read the releases, there will be a install guide in there.

---

## Usage

### 1. Start the Server

Run the server on the remote machine. It must be run as root to access `/bin/login` for PAM authentication.

```bash
sudo ush --server -p 8080
```

### 2. Connect via Client

On your local machine, connect using the server's host/IP.

```bash
ush <host> -p 8080
```

*To exit the session, use the shortcut: `Ctrl + ]*`

---

## Features

* PTY Powered: Supports `vim`, `htop`, `top`, and full shell interactivity with proper terminal resizing.
* Fast: Highly optimized code for minimal overhead.
* Proxy Friendly: Designed to work flawlessly behind Cloudflare, Caddy, and other reverse proxies.

---

## Contributing

`ush.py` aims to be the smallest, most reliable HTTP shell possible. Pull requests regarding further code compression, or better memory management are highly encouraged.
