#!/usr/bin/env -S uv run
# /// script
# dependencies = [
#     "requests",
#     "cryptography",
#     "starlette",
#     "uvicorn",
#     "python-pam",
#     "six",
# ]
# requires-python = "==3.11.*"
# ///

import os, sys, requests, time, select, termios, tty, argparse, getpass, shutil, threading, json, zlib, base64, urllib3, signal, secrets, pty, queue, hashlib, datetime, hmac, ssl, socket, ipaddress, tarfile, resource, subprocess, asyncio, logging
from logging.handlers import TimedRotatingFileHandler
from collections import deque
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography import x509
from cryptography.x509.oid import NameOID

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = "/etc/httpshell"
LOG_DIR = f"{BASE_DIR}/logs"
CADDY_PATH = f"{BASE_DIR}/caddy"
CADDY_CFG = f"{BASE_DIR}/caddyfile"
CERT_PEM = f"{BASE_DIR}/cert.pem"
KEY_PEM = f"{BASE_DIR}/key.pem"

MAX_BUFFER = 1024 * 1024
IDLE_TIMEOUT = 1200
MAX_TOTAL_SESSIONS = 50
MAX_NONCE_HISTORY = 250
AUTH_THROTTLE = {}

sessions = {}
lock = threading.Lock()
cached_priv_rsa = None
server_log = None

def setup_server_logging():
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
    os.chmod(LOG_DIR, 0o700)
    logger = logging.getLogger("HTTPShellServer")
    logger.setLevel(logging.INFO)
    log_path = os.path.join(LOG_DIR, "main.log")
    handler = TimedRotatingFileHandler(log_path, when="D", interval=1, backupCount=7)
    formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def is_domain(hostname):
    try:
        ipaddress.ip_address(hostname)
        return False
    except ValueError: return True

def install_service(port):
    if os.getuid() != 0: 
        sys.exit("[!] Root required. Run with sudo.")
    os.makedirs(BASE_DIR, mode=0o700, exist_ok=True)
    os.chmod(BASE_DIR, 0o700)
    current_script = os.path.abspath(sys.argv[0])
    dest_script = os.path.join(BASE_DIR, "httpshell.py")
    try:
        shutil.copy2(current_script, dest_script)
        os.chmod(dest_script, 0o755)
    except Exception as e:
        sys.exit(f"[!] Failed to copy script to {BASE_DIR}: {e}")
    generate_self_signed_cert()
    ensure_caddy(port, True)
    service_content = f"""[Unit]
Description=HTTPShell Secure Remote Access
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/env -S uv run {dest_script} --server -p {port}
Restart=always
RestartSec=5
WorkingDirectory={BASE_DIR}

[Install]
WantedBy=multi-user.target
"""
    svc_file = "/etc/systemd/system/httpshell.service"
    with open(svc_file, "w") as f: 
        f.write(service_content)
    subprocess.run(["systemctl", "enable", "--now", "httpshell.service"], check=True)
    print(f"[*] HTTPShell installed to {dest_script}")
    print(f"[*] Service active on :{port}")

def cleanup_and_exit(signum=None, frame=None):
    subprocess.run(["pkill", "-f", CADDY_PATH], stderr=subprocess.DEVNULL)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)

def sign_data(key, data): return hmac.new(key, data, hashlib.sha256).digest()
def verify_data(key, data, sig): return hmac.compare_digest(sign_data(key, data), sig)

def generate_self_signed_cert():
    if os.path.exists(CERT_PEM) and os.path.exists(KEY_PEM): return
    os.makedirs(BASE_DIR, mode=0o700, exist_ok=True)
    key = rsa.generate_private_key(65537, 2048)
    sub = iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"httpshell")])
    cert = x509.CertificateBuilder().subject_name(sub).issuer_name(iss).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=False).sign(key, hashes.SHA256())
    with open(KEY_PEM, "wb") as f: f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(CERT_PEM, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))

def session_reaper():
    while True:
        time.sleep(30)
        now = time.time()
        to_del = []
        with lock:
            for sid, s in list(sessions.items()):
                if now - s['last_activity'] > IDLE_TIMEOUT: to_del.append((sid, s['user'], s['ip']))
        for sid, u, ip in to_del:
            with lock:
                s = sessions.pop(sid, None)
                if s:
                    try: 
                        os.close(s['fd']); os.kill(s['pid'], signal.SIGTERM)
                        server_log.info(f"Session timed out: {u} from {ip}")
                    except: pass

async def run_server(port, use_tls):
    import uvicorn, pam, pwd, base64, queue, fcntl, struct, termios, signal
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization as _serial
    global cached_priv_rsa, server_log
    server_log = setup_server_logging()
    generate_self_signed_cert()
    try:
        with open(KEY_PEM, "rb") as f:
            cached_priv_rsa = _serial.load_pem_private_key(f.read(), None)
    except Exception as e:
        server_log.info(f"Failed loading private key: {e}")
        cached_priv_rsa = None
    ensure_caddy(port, use_tls)
    pam_auth = pam.pam()
    threading.Thread(target=session_reaper, daemon=True).start()
    async def auth(request):
        ip = request.query_params.get("i", "unknown")
        now = time.time()
        hist = [t for t in AUTH_THROTTLE.get(ip, []) if now - t < 60]
        if len(hist) >= 5:
            server_log.info(f"AUTH_THROTTLE reached: {ip}")
            return Response(status_code=429)
        AUTH_THROTTLE[ip] = hist + [now]
        if len(sessions) >= MAX_TOTAL_SESSIONS:
            server_log.info(f"MAX_TOTAL_SESSIONS reached: Denied {ip}")
            return Response(status_code=503)
        try:
            body = await request.body()
            d = None
            try:
                raw = base64.b64decode(body)
                if cached_priv_rsa and hasattr(cached_priv_rsa, "decrypt"):
                    try:
                        dec = cached_priv_rsa.decrypt(raw, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        d = json.loads(dec)
                    except Exception as e:
                        server_log.info(f"Auth decrypt failed from {ip}: {e}")
                else:
                    server_log.info(f"No decrypt method on server private key for {ip}")
            except Exception:
                pass
            if d is None:
                try:
                    d = json.loads(body)
                except Exception as e:
                    server_log.info(f"Auth parse failed from {ip}: {e}")
                    return Response(status_code=401)
            u = d.get('user')
            p = d.get('pass')
            c_pub_b64 = d.get('pubx')
            rows = int(d.get('rows', 0)) if isinstance(d, dict) and d.get('rows') is not None else 0
            cols = int(d.get('cols', 0)) if isinstance(d, dict) and d.get('cols') is not None else 0
            if not all([u, p, c_pub_b64]):
                server_log.info(f"Auth missing fields from {ip}: {list(d.keys()) if isinstance(d, dict) else type(d)}")
                return Response(status_code=400)
            try:
                c_pub = base64.b64decode(c_pub_b64)
            except Exception as e:
                server_log.info(f"Auth pubx decode failed from {ip}: {e}")
                return Response(status_code=400)
            if pam_auth.authenticate(u, p):
                server_log.info(f"Login success: {u} from {ip}")
                sx = x25519.X25519PrivateKey.generate()
                sh = sx.exchange(x25519.X25519PublicKey.from_public_bytes(c_pub))
                dr = hashlib.sha256(sh).digest()
                sk, hk, sid = dr[:16], dr[16:], secrets.token_hex(16)
                m, s = os.openpty()
                if rows > 0 and cols > 0:
                    try:
                        ws = struct.pack('HHHH', rows, cols, 0, 0)
                        fcntl.ioctl(s, termios.TIOCSWINSZ, ws)
                    except Exception as e:
                        server_log.info(f"Initial winsize ioctl failed for sid={sid}: {e}")
                pid = os.fork()
                if pid == 0:
                    os.close(m)
                    os.login_tty(s)
                    pw = pwd.getpwnam(u)
                    os.setgroups(os.getgrouplist(u, pw.pw_gid))
                    os.setgid(pw.pw_gid)
                    os.setuid(pw.pw_uid)
                    os.environ.clear()
                    os.environ.update({"TERM": "xterm-256color", "HOME": pw.pw_dir, "USER": u, "PATH": "/usr/local/bin:/usr/bin:/bin"})
                    os.chdir(pw.pw_dir)
                    os.execvp("/bin/bash", ["/bin/bash", "-l"])
                q = queue.Queue(maxsize=5000)
                def rdr(fd_master, si):
                    try:
                        while True:
                            try:
                                if not select.select([fd_master], [], [], 1.0)[0]:
                                    if os.waitpid(pid, os.WNOHANG) != (0, 0):
                                        break
                                    continue
                                buf = os.read(fd_master, 8192)
                                if buf and not q.full():
                                    q.put(buf)
                            except:
                                break
                    finally:
                        with lock:
                            sdict = sessions.pop(si, None)
                        if sdict:
                            try:
                                os.close(sdict.get('fd'))
                            except:
                                pass
                            try:
                                sd = sdict.get('slave_fd')
                                if sd is not None:
                                    os.close(sd)
                            except:
                                pass
                            try:
                                os.kill(sdict.get('pid'), signal.SIGTERM)
                            except:
                                pass
                threading.Thread(target=rdr, args=(m, sid), daemon=True).start()
                with lock:
                    sessions[sid] = {'fd': m, 'slave_fd': s, 'pid': pid, 'q': q, 'k': sk, 'hk': hk, 'user': u, 'ip': ip, 'last_activity': time.time(), 'nonces': deque(maxlen=MAX_NONCE_HISTORY)}
                return JSONResponse({"sid": sid, "srvx": base64.b64encode(sx.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()})
            else:
                server_log.info(f"Login fail: {u} from {ip}")
        except Exception as e:
            server_log.info(f"Auth handler exception from {ip}: {e}")
        return Response(status_code=401)
    async def pull_h(r):
        sid = r.headers.get("X-Session")
        with lock:
            s = sessions.get(sid)
            if not s:
                return Response(status_code=410)
            s['last_activity'] = time.time()
            out = b""
            while not s['q'].empty() and len(out) < MAX_BUFFER:
                out += s['q'].get_nowait()
        n = secrets.token_bytes(12)
        ct = AESGCM(s['k']).encrypt(n, zlib.compress(out), None)
        return Response(sign_data(s['hk'], n + ct) + n + ct)
    async def push_h(r):
        sid = r.headers.get("X-Session")
        with lock:
            s = sessions.get(sid)
            if not s:
                return Response(status_code=410)
            s['last_activity'] = time.time()
        b = await r.body()
        if not b:
            return Response(b"ok")
        sig, n, ct = b[:32], b[32:44], b[44:]
        with lock:
            if n in s['nonces'] or not verify_data(s['hk'], n + ct, sig):
                return Response(status_code=403)
            s['nonces'].append(n)
        try:
            os.write(s['fd'], zlib.decompress(AESGCM(s['k']).decrypt(n, ct, None)))
        except Exception:
            pass
        return Response(b"ok")
    async def resize_h(r):
        sid = r.headers.get("X-Session")
        with lock:
            s = sessions.get(sid)
            if not s:
                return Response(status_code=410)
            s['last_activity'] = time.time()
            pid = s.get('pid')
            fd_slave = s.get('slave_fd')
        b = await r.body()
        if not b:
            return Response(b"ok")
        sig, n, ct = b[:32], b[32:44], b[44:]
        with lock:
            if n in s['nonces'] or not verify_data(s['hk'], n + ct, sig):
                return Response(status_code=403)
            s['nonces'].append(n)
        try:
            pt = AESGCM(s['k']).decrypt(n, ct, None)
            j = json.loads(pt)
            rows = int(j.get("rows", 0))
            cols = int(j.get("cols", 0))
            if rows > 0 and cols > 0 and fd_slave is not None:
                ws = struct.pack('HHHH', rows, cols, 0, 0)
                try:
                    fcntl.ioctl(fd_slave, termios.TIOCSWINSZ, ws)
                    if pid:
                        try:
                            os.kill(pid, signal.SIGWINCH)
                        except:
                            pass
                    server_log.info(f"Resize applied for sid={sid} rows={rows} cols={cols}")
                except Exception as e:
                    server_log.info(f"Resize ioctl failed for sid={sid}: {e}")
        except Exception as e:
            server_log.info(f"Resize handler error: {e}")
        return Response(b"ok")
    app = Starlette(routes=[Route("/auth", auth, methods=["POST"]), Route("/pull", pull_h, methods=["POST"]), Route("/push", push_h, methods=["POST"]), Route("/resize", resize_h, methods=["POST"])])
    server_log.info(f"Server started on port {port}")
    print(f"[*] HTTPShell.py Server running, port {port}.")
    await uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=269, log_level="error")).serve()

def ensure_caddy(port, use_tls=True):
    if not os.path.exists(CADDY_PATH):
        r = requests.get("https://github.com/caddyserver/caddy/releases/download/v2.10.1/caddy_2.10.1_linux_amd64.tar.gz", stream=True)
        with open(f"{BASE_DIR}/caddy.tar.gz", 'wb') as f: shutil.copyfileobj(r.raw, f)
        with tarfile.open(f"{BASE_DIR}/caddy.tar.gz", "r:gz") as tar: tar.extract("caddy", path=BASE_DIR)
        os.chmod(CADDY_PATH, 0o755)
    tls = f"tls {CERT_PEM} {KEY_PEM}" if use_tls else "# No TLS"
    cfg = f":{port} {{\n {tls}\n @shell path /auth /pull /push\n handle @shell {{\n rewrite * {{path}}?i={{remote_host}}\n reverse_proxy 127.0.0.1:269\n }}\n}}"
    with open(CADDY_CFG, "w") as f: f.write(cfg)
    subprocess.run(["pkill", "-f", CADDY_PATH], stderr=subprocess.DEVNULL)
    subprocess.Popen([CADDY_PATH, "run", "--config", CADDY_CFG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_client(args):
    p = 443 if is_domain(args.host) else args.port
    u_base = f"{('http' if args.no_tls else 'https')}://{args.host}:{p}"
    if not args.no_tls:
        try:
            sk = socket.create_connection((args.host, p), timeout=5)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sk, server_hostname=args.host) as ss:
                pub_key = x509.load_der_x509_certificate(ss.getpeercert(binary_form=True)).public_key()
        except:
            sys.exit("This server is down or running with --no-tls or another port.")
    else:
        with open(CERT_PEM, "rb") as f:
            pub_key = x509.load_pem_x509_certificate(f.read()).public_key()

    def get_winsize():
        import fcntl, struct, termios
        s = struct.pack('HHHH', 0, 0, 0, 0)
        data = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, s)
        rows, cols, xp, yp = struct.unpack('HHHH', data)
        return rows, cols

    cx = x25519.X25519PrivateKey.generate()
    pw = getpass.getpass(f"{args.user}@{args.host}'s Password: ")
    try:
        rows, cols = get_winsize()
    except:
        rows, cols = 24, 80
    pay = json.dumps({
        "user": args.user,
        "pass": pw,
        "pubx": base64.b64encode(cx.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
        "rows": rows,
        "cols": cols
    }).encode()

    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes

    if isinstance(pub_key, rsa.RSAPublicKey):
        enc = pub_key.encrypt(pay, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        payload = base64.b64encode(enc)
    else:
        payload = pay

    s = requests.Session()
    try:
        r = s.post(f"{u_base}/auth", data=payload, verify=False)
    except:
        sys.exit("Connection error.")

    if r.status_code != 200:
        sys.exit("Denied.")

    res = r.json()
    sh = cx.exchange(x25519.X25519PublicKey.from_public_bytes(base64.b64decode(res['srvx'])))
    dr = hashlib.sha256(sh).digest()
    sk, hk = dr[:16], dr[16:]
    dead, buf = [False], []
    resize_event = threading.Event()

    def send_resize():
        try:
            r, c = get_winsize()
            j = json.dumps({"type": "resize", "rows": r, "cols": c}).encode()
            n = secrets.token_bytes(12)
            ct = AESGCM(sk).encrypt(n, j, None)
            s.post(f"{u_base}/resize", data=sign_data(hk, n + ct) + n + ct, headers={"X-Session": res['sid']}, verify=False, timeout=2)
        except:
            pass

    def sigwinch_handler(signum, frame):
        resize_event.set()

    signal.signal(signal.SIGWINCH, sigwinch_handler)

    def tx():
        while not dead[0]:
            if resize_event.is_set():
                resize_event.clear()
                send_resize()
            time.sleep(0.02)
            if not buf:
                continue
            d = b"".join(buf)
            buf.clear()
            n = secrets.token_bytes(12)
            ct = AESGCM(sk).encrypt(n, zlib.compress(d), None)
            try:
                s.post(f"{u_base}/push", data=sign_data(hk, n + ct) + n + ct, headers={"X-Session": res['sid']}, verify=False)
            except:
                pass

    def rx():
        while not dead[0]:
            try:
                r = s.post(f"{u_base}/pull", headers={"X-Session": res['sid']}, timeout=10, verify=False)
                if r.status_code == 200 and r.content:
                    sig, n, ct = r.content[:32], r.content[32:44], r.content[44:]
                    if verify_data(hk, n + ct, sig):
                        sys.stdout.write(zlib.decompress(AESGCM(sk).decrypt(n, ct, None)).decode(errors='ignore'))
                        sys.stdout.flush()
                elif r.status_code == 410:
                    dead[0] = True
            except:
                time.sleep(0.1)

    old = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin.fileno())
    threading.Thread(target=tx, daemon=True).start()
    threading.Thread(target=rx, daemon=True).start()
    send_resize()
    try:
        while not dead[0]:
            if select.select([sys.stdin], [], [], 0.1)[0]:
                c = os.read(sys.stdin.fileno(), 1024)
                if b'\x1d' in c:
                    dead[0] = True
                    break
                buf.append(c)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        print("\nConnection Closed.")

if __name__ == "__main__":
    p = argparse.ArgumentParser(
        prog="httpshell.py",
        description="Secure HTTPS remote shell",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Modes:
  Client:
    httpshell.py user host [-p PORT]

  Server:
    httpshell.py --server [-p PORT]

  Install service:
    httpshell.py --server-install [-p PORT]

Exit session with Ctrl+]
"""
    )
    p.add_argument("user", nargs="?")
    p.add_argument("host", nargs="?")
    p.add_argument("-p", "--port", type=int, default=8443)
    p.add_argument("--server", action="store_true")
    p.add_argument("--server-install", action="store_true")
    p.add_argument("--no-tls", action="store_true")
    if len(sys.argv) == 1:
        p.print_help()
        sys.exit(0)
    args = p.parse_args()
    if args.server_install: install_service(args.port)
    elif args.server:
        try:
            asyncio.run(run_server(args.port, not args.no_tls))
        except KeyboardInterrupt:
            cleanup_and_exit()
    elif args.user and args.host:
        run_client(args)
