# HTTPshell.py
> The Open-Source Shell Access over HTTP/HTTPs program, still in alpha/wip.
---
> !![IMPORTANT]
> This is still in alpha.
> Bad code or security vulnerablitys are expected.
---
This program solves one problem:
Can't access your server because TCP or UDP Inbound is non existent and you only have a proxy path or an http/https ports
In mass scale? Then this is for you.
---
Just grab the HTTPshell.py file (Yes, a single file) from the releases and this acts as both as a client & a server.
```
$ httpshell.py 
usage: httpshell.py [-h] [--server] [--server-install] [--uninstall] [-s SECURE] [-f FAST] [user] [host]

positional arguments:
  user
  host

options:
  -h, --help           show this help message and exit
  --server
  --server-install
  --uninstall
  -s, --secure SECURE
  -f, --fast FAST
```
---
Features as of right now:
- It can SH into stuff
- It has color
- It is fast enough
- It interactive
- It works with any shell
- nano/vim/htop/top works
- that's all
---
We are accepting pull requests & contributions.
