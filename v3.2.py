#!/usr/bin/env python3
import sys,os,json,argparse,platform,ipaddress,asyncio,struct,contextlib,hashlib,base64
IS_WIN=platform.system()=="Windows"
APP_CURSOR=False
if IS_WIN:
 import msvcrt,ctypes
 k32=ctypes.windll.kernel32
 hi=k32.GetStdHandle(-10)
 mi=ctypes.c_ulong()
 try:
  ho=k32.GetStdHandle(-11)
  mo=ctypes.c_ulong()
  k32.GetConsoleMode(ho,ctypes.byref(mo))
  k32.SetConsoleMode(ho,mo.value|4)
  k32.GetConsoleMode(hi,ctypes.byref(mi))
  k32.SetConsoleMode(hi,mi.value&~1)
 except:pass
else:import tty,termios,fcntl,select

_WS_GUID="258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
class _WS:
 def __init__(s,r,w,c):
  s._r,s._w,s._c,s._q,s._x=r,w,c,asyncio.Queue(),0
  asyncio.create_task(s._l())
 async def _l(s):
  try:
   while 1:
    m=await s._f()
    if m is None:break
    await s._q.put(m)
  except:pass
  await s._q.put(None)
 async def _f(s):
  h=await s._r.readexactly(2)
  if not h:return
  b1,b2=h[0],h[1];op=b1&0xF;l=b2&0x7F;m=(b2>>7)&1
  if l==126:l=struct.unpack(">H",await s._r.readexactly(2))[0]
  elif l==127:l=struct.unpack(">Q",await s._r.readexactly(8))[0]
  mk=None
  if m:mk=await s._r.readexactly(4)
  p=await s._r.readexactly(l)
  if mk:p=bytes(b^mk[i%4] for i,b in enumerate(p))
  if op==8:s._c=1;return
  if op==9:await s._sw(0xA,p or b"");return await s._f()
  if op==0xA:return await s._f()
  return p.decode()if op==1 else p
 async def _sw(s,op,p):
  l=len(p);h=bytearray([0x80|op])
  if l>65535:h.append(0xFF if s._c else 127);h.extend(struct.pack(">Q",l))
  elif l>125:h.append(0xFE if s._c else 126);h.extend(struct.pack(">H",l))
  else:h.append(0x80|l if s._c else l)
  if s._c:
   mk=os.urandom(4);h.extend(mk)
   p=bytes(b^mk[i%4] for i,b in enumerate(p))
  s._w.write(bytes(h)+p);await s._w.drain()
 async def send(s,d):
  if isinstance(d,str):await s._sw(1,d.encode())
  else:await s._sw(2,d)
 async def recv(s):
  m=await s._q.get()
  if m is None:raise ConnectionError
  return m
 def __aiter__(s):return s
 async def __anext__(s):
  m=await s._q.get()
  if m is None:raise StopAsyncIteration
  return m
 async def close(s):
  if not s._c:
   s._c=1
   try:await s._sw(8,b"")
   except:pass
   try:s._w.close()
   except:pass

async def _ws_connect(u,kw):
 ssl=0;h=u
 if h.startswith("ws://"):h=h[5:]
 elif h.startswith("wss://"):h=h[6:];ssl=1
 else:raise ValueError("bad ws uri")
 p=h.split("/",1);host=p[0];path="/"+(p[1]if len(p)>1 else"")
 port=443 if ssl and":"not in host else 80 if":"not in host else int(host.split(":")[1])
 if":"in host:host=host.split(":")[0]
 r,w=await asyncio.open_connection(host,port,ssl=ssl)
 k=base64.b64encode(os.urandom(16)).decode()
 req=f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {k}\r\nSec-WebSocket-Version: 13\r\n"
 for n,v in kw.get("additional_headers",kw.get("extra_headers",{})).items():req+=f"{n}: {v}\r\n"
 req+="\r\n"
 w.write(req.encode());await w.drain()
 d=b""
 while b"\r\n\r\n"not in d:d+=await r.read(4096)
 if b"101"not in d.split(b"\r\n")[0]:raise ConnectionError("handshake failed")
 a=base64.b64encode(hashlib.sha1((k+_WS_GUID).encode()).digest()).decode()
 if a.encode()not in d:raise ConnectionError("accept mismatch")
 return _WS(r,w,1)

async def _ws_serve(h,po):
 async def o(r,w):
  d=b""
  while b"\r\n\r\n"not in d:d+=await r.read(4096)
  k=""
  for l in d.decode().split("\r\n"):
   if l.lower().startswith("sec-websocket-key:"):k=l.split(":",1)[1].strip();break
  if not k:return
  a=base64.b64encode(hashlib.sha1((k+_WS_GUID).encode()).digest()).decode()
  w.write(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {a}\r\n\r\n".encode());await w.drain()
  await h(_WS(r,w,0))
 s=await asyncio.start_server(o,"0.0.0.0",po);print(f"[ush] server running on :{po}")
 async with s:await s.serve_forever()

async def run_c(h,p,verbose=False):
 s=asyncio.Event()
 s.headers={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"}
 uri=f"{h}:{p}" if "://" in h else f"ws://{h}:{p}"
 async def close_ws(ws):
  if not s.is_set():s.set()
  with contextlib.suppress(Exception):await ws.close()
 async def rx(ws):
  global APP_CURSOR
  try:
   async for m in ws:
    if isinstance(m,str):
     try:
      d=json.loads(m)
      if d.get("type")=="control"and d.get("action")=="close":
       await close_ws(ws)
       break
      if d.get("type")=="resize":continue
     except Exception as e:
      if verbose:print(f"rx json error: {e}",file=sys.stderr)
     sys.stdout.write(m)
     sys.stdout.flush()
    else:
     if b"\x1b[?1h"in m:APP_CURSOR=True
     if b"\x1b[?1l"in m:APP_CURSOR=False
     sys.stdout.buffer.write(m)
     sys.stdout.buffer.flush()
  except Exception as e:
   if verbose:print(f"rx error: {e}",file=sys.stderr)
  s.set()
 async def tx(ws):
  global APP_CURSOR
  l=asyncio.get_running_loop()
  def rp():
   try:
    if select.select([0],[],[],0.1)[0]:
     return os.read(0,4096)
   except OSError:pass
   return b""
  try:
   while not s.is_set():
    if IS_WIN:
     if msvcrt.kbhit():
      b=bytearray()
      x=False
      while True:
       while msvcrt.kbhit():
        c=msvcrt.getwch()
        if c in ("\x00","\xe0"):
         c2=msvcrt.getwch()
         if APP_CURSOR:d={"H":b"\x1bOA","P":b"\x1bOB","M":b"\x1bOC","K":b"\x1bOD"}.get(c2)
         else:d={"H":b"\x1b[A","P":b"\x1b[B","M":b"\x1b[C","K":b"\x1b[D"}.get(c2)
         if not d:d={"R":b"\x1b[2~","S":b"\x1b[3~","G":b"\x1b[H","O":b"\x1b[F","I":b"\x1b[5~","Q":b"\x1b[6~","D":b"\x1b[21~"}.get(c2,b"")
         if d:b.extend(d)
        else:
         if c=="\x1d":
          await close_ws(ws)
          x=True
          break
         if c=="\x08":b.extend(b"\x7f")
         else:b.extend(c.encode("utf-8","ignore"))
       if x:break
       await asyncio.sleep(0.005)
       if not msvcrt.kbhit():break
      if b:await ws.send(bytes(b))
      if x:break
     else:await asyncio.sleep(0.01)
    else:
     c=await l.run_in_executor(None,rp)
     if c:
      if b"\x1d"in c:
       await close_ws(ws)
       break
      await ws.send(c)
  except Exception as e:
   if verbose:print(f"tx error: {e}",file=sys.stderr)
  s.set()
 async def poll_sz(ws):
  try:
   o=os.get_terminal_size()
   await ws.send(json.dumps({"type":"resize","rows":o.lines,"cols":o.columns}))
   while not s.is_set():
    await asyncio.sleep(1)
    n=os.get_terminal_size()
    if n!=o:
     o=n
     await ws.send(json.dumps({"type":"resize","rows":n.lines,"cols":n.columns}))
  except Exception as e:
   if verbose:print(f"poll_sz error: {e}",file=sys.stderr)
  s.set()
 if not IS_WIN:
  ot=termios.tcgetattr(0)
  tty.setraw(0)
  ct=termios.tcgetattr(0)
  ct[3]&=~termios.ISIG
  termios.tcsetattr(0,termios.TCSADRAIN,ct)
 try:
  ws=await _ws_connect(uri,{"additional_headers":s.headers})
  await asyncio.gather(rx(ws),tx(ws),poll_sz(ws),return_exceptions=True)
  await ws.close()
 except Exception as e:
  if verbose:print(f"Fail: {e}")
  else:print("Fail")
 finally:
  if not IS_WIN:termios.tcsetattr(0,termios.TCSADRAIN,ot)
  else:
   try:k32.SetConsoleMode(hi,mi.value)
   except:pass
  print("Connection Closed.")

async def run_s(p,daemon=False):
 if platform.system()!="Linux":sys.exit("Server runs on Linux only.")
 if daemon:
  if os.fork()>0:sys.exit(0)
  os.setsid()
  if os.fork()>0:sys.exit(0)
 async def h(ws):
  pid=m=sl=None
  l=asyncio.get_running_loop()
  q=asyncio.Queue()
  stop=asyncio.Event()
  async def close_client():
   if stop.is_set():return
   stop.set()
   with contextlib.suppress(Exception):await ws.send(json.dumps({"type":"control","action":"close"}))
   with contextlib.suppress(Exception):await ws.close()
   with contextlib.suppress(Exception):q.put_nowait(None)
  try:
   try:
    init=json.loads(await ws.recv())
    r=int(init.get("rows",24))
    c=int(init.get("cols",80))
   except Exception:
    return
   m,sl=os.openpty()
   fcntl.ioctl(sl,21524,struct.pack("HHHH",r,c,0,0))
   pid=os.fork()
   if pid==0:
    os.close(m)
    os.login_tty(sl)
    os.execvp("/bin/login",["/bin/login"])
   def rd():
    try:
     d=os.read(m,16384)
     if d:q.put_nowait(d)
    except Exception:
     q.put_nowait(None)
   l.add_reader(m,rd)
   async def ws_r():
    try:
     async for msg in ws:
      if isinstance(msg,bytes):
       with contextlib.suppress(Exception):os.write(m,msg)
      else:
       try:j=json.loads(msg)
       except Exception:continue
       if j.get("type")=="resize":
        with contextlib.suppress(Exception):
         fcntl.ioctl(sl,21524,struct.pack("HHHH",int(j["rows"]),int(j["cols"]),0,0))
         os.kill(pid,28)
    except Exception:
     pass
    finally:
     await close_client()
     q.put_nowait(None)
   async def ws_w():
    while True:
     d=await q.get()
     if d is None:break
     with contextlib.suppress(Exception):await ws.send(d)
   async def reap():
    try:
     await l.run_in_executor(None,os.waitpid,pid,0)
    finally:
     await close_client()
   await asyncio.gather(ws_r(),ws_w(),reap(),return_exceptions=True)
  finally:
   with contextlib.suppress(Exception):
    if m is not None:l.remove_reader(m)
   with contextlib.suppress(Exception):
    if m is not None:os.close(m)
   with contextlib.suppress(Exception):
    if sl is not None:os.close(sl)
   with contextlib.suppress(Exception):
    if pid:os.kill(pid,9)
 await _ws_serve(h,p)

if __name__=="__main__":
 p=argparse.ArgumentParser(description="ush.py v3.2")
 p.add_argument("--server","-s",action="store_true")
 p.add_argument("-p",type=int,default=8080)
 p.add_argument("-d",action="store_true")
 p.add_argument("-v","--verbose",action="store_true")
 p.add_argument("host",nargs="?")
 a=p.parse_args()
 if a.host and "-p" not in sys.argv:
  try:ipaddress.ip_address(a.host)
  except:a.p=80
 try:
  if a.server:asyncio.run(run_s(a.p,a.d))
  elif a.host:asyncio.run(run_c(a.host,a.p,a.verbose))
  else:p.print_help()
 except KeyboardInterrupt:print("Connection Closed.")
