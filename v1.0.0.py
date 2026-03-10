#!/usr/bin/env python3
import os, sys, tty, termios, select, threading, queue, fcntl, struct, signal, json, time, argparse, requests
from http.server import BaseHTTPRequestHandler, HTTPServer
M_BUF, MAX_Q, sess, lock = 1024*1024, 50, {}, threading.Lock()
class H(BaseHTTPRequestHandler):
    def _s(self, d=b"", c=200): self.send_response(c); self.end_headers(); self.wfile.write(d)
    def do_POST(self):
        L, sid, path = int(self.headers.get("Content-Length", 0)), self.headers.get("X-Session"), self.path
        body = self.rfile.read(L)
        if path == "/auth":
            try:
                d = json.loads(body); r, c = int(d.get("rows", 24)), int(d.get("cols", 80)); m, s = os.openpty(); fcntl.ioctl(s, 21524, struct.pack("HHHH", r, c, 0, 0))
                if (pid := os.fork()) == 0: os.close(m); os.login_tty(s); os.execvp("/bin/login", ["/bin/login"])
                sid = os.urandom(32).hex(); sess[sid] = {"fd": m, "slave_fd": s, "pid": pid, "q": queue.Queue(MAX_Q)}
                threading.Thread(target=self.rd, args=(m, sid), daemon=True).start(); self._s(json.dumps({"sid": sid}).encode())
            except: self._s(b"fail", 401)
        else:
            if not (s := sess.get(sid)): return self._s(b"", 410)
            if path == "/pull":
                out = b""
                while not s["q"].empty() and len(out) < M_BUF: out += s["q"].get()
                self._s(out)
            elif path == "/push": os.write(s["fd"], body); self._s(b"ok")
            elif path == "/resize":
                d = json.loads(body); fcntl.ioctl(s["slave_fd"], 21524, struct.pack("HHHH", int(d["rows"]), int(d["cols"]), 0, 0)); os.kill(s["pid"], 28); self._s(b"ok")
    def rd(self, f, id):
        while (s := sess.get(id)):
            try:
                if select.select([f], [], [], 0.5)[0]: 
                    buf = os.read(f, 8192)
                    if buf: s["q"].put(buf)
                elif os.waitpid(s["pid"], 1) != (0,0): break
            except: break
        sess.pop(id, None)
def get_ws(): return struct.unpack("HHHH", fcntl.ioctl(0, 21523, b'\x00'*8))[:2]
def run_c(h, p):
    S, d_ed, buf, ev = requests.Session(), [0], [], threading.Event(); r, c = get_ws(); url = f"http://{h}:{p}"
    try: sid = S.post(f"{url}/auth", json={"rows": r, "cols": c}).json()["sid"]
    except: return print("Fail")
    def tx():
        while not d_ed[0]:
            if ev.is_set():
                ev.clear(); r, c = get_ws()
                try: S.post(f"{url}/resize", headers={"X-Session": sid}, json={"rows": r, "cols": c})
                except: pass
            if buf: 
                try: d = b"".join(buf); buf.clear(); S.post(f"{url}/push", headers={"X-Session": sid}, data=d)
                except: pass
            else: time.sleep(0.01)
    def rx():
        while not d_ed[0]:
            try:
                r = S.post(f"{url}/pull", headers={"X-Session": sid}, timeout=5)
                if r.status_code == 200: sys.stdout.write(r.content.decode(errors="ignore")); sys.stdout.flush()
                elif r.status_code == 410: d_ed[0] = 1
            except: pass
    signal.signal(28, lambda x,y: ev.set()); old = termios.tcgetattr(0); tty.setraw(0)
    try:
        [threading.Thread(target=f, daemon=True).start() for f in (tx, rx)]
        while not d_ed[0]:
            if select.select([0], [], [], 0.05)[0]:
                if b"\x1d" in (ch := os.read(0, 4096)): break
                buf.append(ch)
    finally: termios.tcsetattr(0, 2, old); print("\nConnection closed.")
if __name__ == "__main__":
    p = argparse.ArgumentParser(description="ush.py"); p.add_argument("--server", "-s", action="store_true"); p.add_argument("-p", type=int, default=8080); p.add_argument("-d", action="store_true"); p.add_argument("host", nargs="?"); a = p.parse_args()
    if a.server:
        if a.d: 
            if os.fork() > 0: sys.exit(0)
            os.setsid()
            if os.fork() > 0: sys.exit(0)
        print(f"[ushs] server is running on :{a.p}"); HTTPServer(("0.0.0.0", a.p), H).serve_forever()
    elif a.host: run_c(a.host, a.p)
    else: p.print_help()
