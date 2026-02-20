#!/usr/bin/env -S uv run
# /// script
# dependencies = [
#   "requests",
#   "cryptography",
#   "starlette",
#   "uvicorn",
#   "python-pam",
#   "six",
# ]
# ///

import os, sys, requests, time, select, termios, tty, argparse, getpass, struct, shutil, threading, json, zlib, base64, re, urllib3, signal, secrets, fcntl, pty, queue, hashlib, datetime, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BASE_DIR = "/etc/httpshell"
CONFIG_PATH = f"{BASE_DIR}/config.txt"
PYPROJECT_PATH = f"{BASE_DIR}/pyproject.toml"

def sign_data(key, data): return hmac.new(key, data, hashlib.sha256).digest()
def verify_data(key, data, sig): return hmac.compare_digest(sign_data(key, data), sig)

def setup_env():
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR, mode=0o700)
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            f.write("# HTTPShell Config\naport 8443\nbport 8080\n\n# If you are using cloudflare tunnel, please change this to 0 & use http://urip:aport\ndualstack 1\n\nrootlogin 0\nloginmax 3\nsessionmax 0\nrandomfingerprintonstartup 0\nkeys \npasswordauth 1\nscert /etc/httpshell/cert.pem\nskey /etc/httpshell/key.pem\n")
    if not os.path.exists(PYPROJECT_PATH):
        with open(PYPROJECT_PATH, "w") as f:
            f.write('[project]\nname = "httpshell"\nversion = "0.1.0"\nrequires-python = ">=3.12"\ndependencies = [\n    "cryptography>=46.0.5",\n    "python-pam>=2.0.2",\n    "six>=1.17.0",\n    "starlette>=0.52.1",\n    "uvicorn>=0.40.0",\n    "requests>=2.31.0",\n]\n')

def load_config():
    cfg = {'aport': 8443, 'bport': 8080, 'dualstack': 1, 'rootlogin': 0, 'loginmax': 3, 'sessionmax': 0, 'randomfingerprintonstartup': 0, 'keys': [], 'passwordauth': 1, 'scert': f'{BASE_DIR}/cert.pem', 'skey': f'{BASE_DIR}/key.pem'}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip(): continue
                p = line.split()
                if len(p) < 2: continue
                k, v = p[0], " ".join(p[1:])
                if k in ['aport', 'bport', 'dualstack', 'rootlogin', 'loginmax', 'sessionmax', 'randomfingerprintonstartup', 'passwordauth']: cfg[k] = int(v)
                elif k == 'keys': cfg[k] = [x.strip() for x in v.split(",") if x.strip()]
                else: cfg[k] = v
    return cfg

def generate_ssl_if_missing(cert_path, key_path):
    if os.path.exists(cert_path) and os.path.exists(key_path): return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sub = iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"httpshell-internal")])
    cert = x509.CertificateBuilder().subject_name(sub).issuer_name(iss).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False).sign(key, hashes.SHA256())
    with open(key_path, "wb") as f: f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(cert_path, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))

def run_server():
    import uvicorn, pam, pwd
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route
    setup_env()
    C = load_config()
    generate_ssl_if_missing(C['scert'], C['skey'])
    sessions, ip_logins, lock = {}, {}, threading.Lock()
    pam_auth = pam.pam()
    def get_fp():
        path = f"{BASE_DIR}/host.key"
        if C['randomfingerprintonstartup'] or not os.path.exists(path):
            k = ed25519.Ed25519PrivateKey.generate()
            if not C['randomfingerprintonstartup']:
                with open(path, "wb") as f: f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        else:
            with open(path, "rb") as f: k = serialization.load_pem_private_key(f.read(), None)
        return hashlib.sha256(k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    FINGERPRINT = get_fp()
    async def auth(request):
        ip = request.client.host
        with lock:
            if C['loginmax'] > 0 and ip_logins.get(ip, 0) >= C['loginmax']: return JSONResponse({"ok": False}, status_code=429)
        d = await request.json()
        u = d.get("user")
        if u == "root" and not C['rootlogin']: return JSONResponse({"ok": False}, status_code=401)
        valid = False
        if C['passwordauth'] and pam_auth.authenticate(u, d.get("pass", ""), service="login"): valid = True
        if valid:
            sid, sk = secrets.token_hex(32), AESGCM.generate_key(256)
            hk = secrets.token_bytes(32)
            m, s = os.openpty()
            if os.fork() == 0:
                os.close(m)
                fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", d["rows"], d["cols"], 0, 0))
                os.login_tty(s)
                pw_entry = pwd.getpwnam(u)
                os.setgid(pw_entry.pw_gid); os.setuid(pw_entry.pw_uid); os.chdir(pw_entry.pw_dir)
                os.environ.update({"TERM": "xterm-256color", "HOME": pw_entry.pw_dir, "USER": u})
                os.execvp("/bin/bash", ["/bin/bash", "-l"])
            os.close(s)
            q = queue.Queue()
            def rdr(fd, q, si):
                while True:
                    try:
                        c = os.read(fd, 16384)
                        if not c: break
                        q.put(c)
                    except: break
                if si in sessions: sessions[si]["active"] = False
            threading.Thread(target=rdr, args=(m, q, sid), daemon=True).start()
            sessions[sid] = {"fd": m, "q": q, "k": sk, "hk": hk, "active": True, "sin": 0, "sout": 0, "ts": time.time()}
            return JSONResponse({"ok": True, "sid": sid, "key": base64.b64encode(sk).decode(), "hkey": base64.b64encode(hk).decode()})
        with lock: ip_logins[ip] = ip_logins.get(ip, 0) + 1
        return JSONResponse({"ok": False}, status_code=401)
    async def pull(request):
        s = sessions.get(request.headers.get("X-Session"))
        if not s: return Response(status_code=404)
        s["ts"] = time.time()
        b = b""
        while not s["q"].empty(): b += s["q"].get_nowait()
        n = struct.pack(">Q", s["sout"]).rjust(12, b'\x00')
        s["sout"] += 1
        ct = AESGCM(s["k"]).encrypt(n, zlib.compress(b), None)
        sig = sign_data(s["hk"], n + ct)
        return Response(sig + n + ct, headers={"X-Status": "active" if s["active"] else "dead"})
    async def push(request):
        s = sessions.get(request.headers.get("X-Session"))
        if not s: return Response(status_code=403)
        s["ts"] = time.time()
        body = await request.body()
        if body:
            sig, n, ct = body[:32], body[32:44], body[44:]
            if not verify_data(s["hk"], n + ct, sig): return Response(status_code=403)
            try:
                seq = struct.unpack(">Q", n[4:])[0]
                if seq <= s["sin"] and s["sin"] != 0: return Response(status_code=400)
                os.write(s["fd"], zlib.decompress(AESGCM(s["k"]).decrypt(n, ct, None)))
                s["sin"] = seq
            except: return Response(status_code=400)
        return Response(b"ok")
    app = Starlette(routes=[Route("/hs", lambda r: JSONResponse({"fp": FINGERPRINT})), Route("/auth", auth, methods=["POST"]), Route("/pull", pull, methods=["POST"]), Route("/push", push, methods=["POST"])])
    if C['dualstack']:
        threading.Thread(target=lambda: uvicorn.run(app, host="0.0.0.0", port=C['aport'], ssl_keyfile=C['skey'], ssl_certfile=C['scert'], log_level="error"), daemon=True).start()
        uvicorn.run(app, host="0.0.0.0", port=C['bport'], log_level="error")
    else:
        ssl_args = {"ssl_keyfile": C['skey'], "ssl_certfile": C['scert']} if os.path.exists(C['scert']) else {}
        uvicorn.run(app, host="0.0.0.0", port=C['aport'], log_level="error", **ssl_args)

def run_client(args):
    def is_domain(t): return re.search(r'[a-zA-Z]', t) is not None
    S_PORT = args.secure or (443 if is_domain(args.host) else 8443)
    F_PORT = args.fast or (80 if is_domain(args.host) else 8080)
    A_URL, D_URL = f"https://{args.host}:{S_PORT}", f"http://{args.host}:{F_PORT}"
    TRUST_F = os.path.expanduser("~/.httpshell_trust")
    K, HK, SID, sin, sout, dead = None, None, None, 0, 0, False
    buf, lock = b"", threading.Lock()
    resize_event = threading.Event()
    def verify_trust(ip, fp):
        db = {}
        if os.path.exists(TRUST_F):
            try:
                with open(TRUST_F, "r") as f: db = json.load(f)
            except: pass
        if ip in db:
            if db[ip] != fp:
                print("\r\r@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                print("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!    @")
                print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                print("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!")
                print("Someone could be eavesdropping on you right now.")
                print(f"Fingerprint: SHA256:{fp}")
                sys.exit(1)
            return
        print(f"The authenticity of host '{ip}' can't be established.")
        print(f"Fingerprint: SHA256:{fp}")
        if input("Are you sure you want to continue connecting (yes/no)? ").lower() != "yes": sys.exit(0)
        db[ip] = fp
        with open(TRUST_F, "w") as f: json.dump(db, f)
    def tx_loop():
        nonlocal sout, buf, dead
        s = requests.Session()
        while not dead:
            time.sleep(0.04)
            h = {"X-Session": SID}
            with lock: d, buf = buf, b""
            if not d: continue
            sout += 1
            n = struct.pack(">Q", sout).rjust(12, b'\x00')
            ct = AESGCM(K).encrypt(n, zlib.compress(d), None)
            sig = sign_data(HK, n + ct)
            try:
                s.post(f"{A_URL}/push", data=sig+n+ct, headers=h, timeout=5, verify=False)
            except: pass

    def rx_loop():
        nonlocal sin, dead
        s = requests.Session()
        while not dead:
            try:
                r = s.post(f"{A_URL}/pull", headers={"X-Session": SID}, timeout=10, verify=False)
                if r.content:
                    sig, n, ct = r.content[:32], r.content[32:44], r.content[44:]
                    if verify_data(HK, n + ct, sig):
                        sys.stdout.write(zlib.decompress(AESGCM(K).decrypt(n, ct, None)).decode(errors='ignore'))
                        sys.stdout.flush()
                if r.headers.get("X-Status") == "dead": dead = True
            except: pass
    hs = requests.get(f"{A_URL}/hs", verify=False, timeout=5).json()
    verify_trust(args.host, hs['fp'])
    pw = getpass.getpass(f"{args.user}@{args.host} password: ")
    cols, rows = shutil.get_terminal_size()
    res = requests.post(f"{A_URL}/auth", json={"user": args.user, "pass": pw, "rows": rows, "cols": cols}, verify=False).json()
    if not res.get("ok"): sys.exit("Access denied.")
    SID, K = res['sid'], base64.b64decode(res['key'])
    HK = base64.b64decode(res['hkey'])
    stash = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin.fileno())
    threading.Thread(target=tx_loop, daemon=True).start()
    threading.Thread(target=rx_loop, daemon=True).start()
    try:
        while not dead:
            if select.select([sys.stdin], [], [], 0.1)[0]:
                char = os.read(sys.stdin.fileno(), 1024)
                with lock: buf += char
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, stash)

def install_service():
    if os.getuid() != 0: sys.exit("Install requires root.")
    uv_bin = shutil.which("uv")
    if not uv_bin: sys.exit("Error: 'uv' not found.")
    setup_env()
    script_dest = f"{BASE_DIR}/app.py"
    shutil.copyfile(os.path.abspath(__file__), script_dest)
    os.chmod(script_dest, 0o755)
    if os.path.exists("/run/systemd/system"):
        unit = f"[Unit]\nDescription=HTTPShell\nAfter=network.target\n\n[Service]\nWorkingDirectory={BASE_DIR}\nExecStart={uv_bin} run app.py --server\nRestart=always\nUser=root\n\n[Install]\nWantedBy=multi-user.target\n"
        with open("/etc/systemd/system/httpshell.service", "w") as f: f.write(unit)
        os.system("systemctl daemon-reload && systemctl enable httpshell && systemctl start httpshell")
    elif os.path.exists("/sbin/openrc-run"):
        init = f'#!/sbin/openrc-run\ncommand="{uv_bin}"\ncommand_args="run app.py --server"\ncommand_dir="{BASE_DIR}"\ncommand_background="yes"\npidfile="/run/httpshell.pid"\n'
        with open("/etc/init.d/httpshell", "w") as f: f.write(init)
        os.chmod("/etc/init.d/httpshell", 0o755)
        os.system("rc-update add httpshell default && rc-service httpshell start")
    print(f"Done. Installed at {BASE_DIR}")

def uninstall_service():
    if os.getuid() != 0: sys.exit("Uninstall requires root.")
    if os.path.exists("/etc/systemd/system/httpshell.service"):
        os.system("systemctl stop httpshell && systemctl disable httpshell")
        os.remove("/etc/systemd/system/httpshell.service")
        os.system("systemctl daemon-reload")
    if os.path.exists("/etc/init.d/httpshell"):
        os.system("rc-service httpshell stop && rc-update del httpshell default")
        os.remove("/etc/init.d/httpshell")
    if os.path.exists(BASE_DIR): shutil.rmtree(BASE_DIR)
    print("Uninstalled.")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("user", nargs="?"); p.add_argument("host", nargs="?")
    p.add_argument("--server", action="store_true")
    p.add_argument("--server-install", action="store_true")
    p.add_argument("--uninstall", action="store_true")
    p.add_argument("-s", "--secure", type=int); p.add_argument("-f", "--fast", type=int)
    args = p.parse_args()
    if args.uninstall: uninstall_service()
    elif args.server_install: install_service()
    elif args.server: run_server()
    elif args.user and args.host: run_client(args)
    else: p.print_help()
