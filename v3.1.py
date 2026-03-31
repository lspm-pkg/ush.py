#!/usr/bin/env python3
import sys,os,json,argparse,platform,ipaddress,asyncio,struct,contextlib
try:import websockets
except:sys.exit("pip install websockets")
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

async def run_c(h,p,verbose=False):
 s=asyncio.Event()
 s.headers={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"}
 uri=f"{h}:{p}" if "://" in h else f"{'wss' if p in (443,8443) else 'ws'}://{h}:{p}"
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
  def rp():return os.read(0,4096) if select.select([0],[],[],0.1)[0] else b""
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
   def sz():
    if IS_WIN:
     try:return os.get_terminal_size()
     except:return(24,80)
    try:return struct.unpack("HH",fcntl.ioctl(0,21523,b"\x00"*4))
    except:return(24,80)
   o=sz()
   await ws.send(json.dumps({"type":"resize","rows":getattr(o,"lines",o[0]),"cols":getattr(o,"columns",o[1])}))
   while not s.is_set():
    await asyncio.sleep(1)
    n=sz()
    if n!=o:
     o=n
     await ws.send(json.dumps({"type":"resize","rows":getattr(n,"lines",n[0]),"cols":getattr(n,"columns",n[1])}))
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
  ws_ver=int(websockets.__version__.split(".")[0])
  kw={"additional_headers":s.headers}if ws_ver>=14 else{"extra_headers":s.headers}
  async with websockets.connect(uri,**kw,ping_interval=20,ping_timeout=60)as ws:
   await asyncio.gather(rx(ws),tx(ws),poll_sz(ws),return_exceptions=True)
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
 async def h(ws,_=None):
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
 print(f"[ush] server running on :{p}")
 async with websockets.serve(h,"0.0.0.0",p,ping_interval=20,ping_timeout=60):await asyncio.Future()

if __name__=="__main__":
 p=argparse.ArgumentParser(description="ush.py v3.1")
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
