#!/usr/bin/env python3
import sys,os,json,argparse,platform,ipaddress,asyncio,struct,contextlib
try: import websockets
except: sys.exit("pip install websockets")
IS_WIN=platform.system()=="Windows"
if IS_WIN: import msvcrt
else: import tty,termios,fcntl,select

async def run_c(h,p,verbose=False):
 s=asyncio.Event();s.headers={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"}
 uri=f"{h}:{p}" if "://" in h else f"{'wss' if p in (443,8443) else 'ws'}://{h}:{p}"
 async def close_ws(ws): 
  if not s.is_set(): s.set()
  with contextlib.suppress(Exception): await ws.close()
 async def rx(ws):
  try:
   async for m in ws:
    if isinstance(m,str):
     try:
      d=json.loads(m)
      if d.get("type")=="control"and d.get("action")=="close": await close_ws(ws);break
      if d.get("type")=="resize": continue
     except: pass
     sys.stdout.write(m);sys.stdout.flush()
    else: sys.stdout.buffer.write(m);sys.stdout.buffer.flush()
  except: pass
  s.set()
 async def tx(ws):
  l=asyncio.get_running_loop()
  def rp(): return os.read(0,4096) if select.select([0],[],[],0.1)[0] else b""
  try:
   while not s.is_set():
    if IS_WIN:
     if msvcrt.kbhit():
      c=msvcrt.getwch()
      if c=="\x1d": await close_ws(ws);break
      await ws.send(c.encode("utf-8","ignore"))
     else: await asyncio.sleep(0.01)
    else:
     c=await l.run_in_executor(None,rp)
     if c:
      if b"\x1d" in c: await close_ws(ws);break
      await ws.send(c)
  except: pass
  s.set()
 async def poll_sz(ws):
  def sz():
   if IS_WIN: return os.get_terminal_size()
   try: return struct.unpack("HH",fcntl.ioctl(0,21523,b"\x00"*4))
   except: return (24,80)
  o=sz()
  await ws.send(json.dumps({"type":"resize","rows":getattr(o,"lines",o[0]),"cols":getattr(o,"columns",o[1])}))
  while not s.is_set():
   await asyncio.sleep(0.5)
   n=sz()
   if n!=o:o=n;await ws.send(json.dumps({"type":"resize","rows":getattr(n,"lines",n[0]),"cols":getattr(n,"columns",n[1])}))
 if not IS_WIN:
  ot=termios.tcgetattr(0)
  tty.setraw(0);ct=termios.tcgetattr(0);ct[3]&=~termios.ISIG;termios.tcsetattr(0,termios.TCSADRAIN,ct)
 try: async with websockets.connect(uri,extra_headers=s.headers,ping_interval=20,ping_timeout=20) as ws: await asyncio.gather(rx(ws),tx(ws),poll_sz(ws))
 finally: 
  if not IS_WIN: termios.tcsetattr(0,termios.TCSADRAIN,ot)
  print("Connection Closed." if not verbose else "Connection Closed.")

async def run_s(p,daemon=False):
 if platform.system()!="Linux": sys.exit("Server runs on Linux only.")
 if daemon:
  if os.fork()>0: sys.exit(0)
  os.setsid()
  if os.fork()>0: sys.exit(0)
 async def h(ws,_=None):
  pid=m=sl=None;l=asyncio.get_running_loop();q=asyncio.Queue();stop=asyncio.Event()
  async def close_client():
   if stop.is_set(): return
   stop.set()
   with contextlib.suppress(Exception): await ws.send(json.dumps({"type":"control","action":"close"}))
   with contextlib.suppress(Exception): await ws.close()
   with contextlib.suppress(Exception): q.put_nowait(None)
  try:
   try:r,c=map(int,(json.loads(await ws.recv()).get("rows",24),json.loads(await ws.recv()).get("cols",80)))
   except: return
   m,sl=os.openpty();fcntl.ioctl(sl,21524,struct.pack("HHHH",r,c,0,0));pid=os.fork()
   if pid==0: os.close(m);os.login_tty(sl);os.execvp("/bin/login",["/bin/login"])
   def rd():
    try:
     d=os.read(m,16384)
     q.put_nowait(d if d else None)
    except: q.put_nowait(None)
   l.add_reader(m,rd)
   async def ws_r():
    try:
     async for msg in ws:
      if isinstance(msg,bytes): with contextlib.suppress(Exception): os.write(m,msg)
      else:
       try:j=json.loads(msg)
       except: continue
       if j.get("type")=="resize": with contextlib.suppress(Exception): fcntl.ioctl(sl,21524,struct.pack("HHHH",int(j["rows"]),int(j["cols"]),0,0));os.kill(pid,28)
    finally: await close_client();q.put_nowait(None)
   async def ws_w():
    while True:
     d=await q.get()
     if d is None: break
     with contextlib.suppress(Exception): await ws.send(d)
   async def reap(): await l.run_in_executor(None,os.waitpid,pid,0);await close_client()
   await asyncio.gather(ws_r(),ws_w(),reap())
  finally:
   with contextlib.suppress(Exception):
    [l.remove_reader(m),os.close(m),os.close(sl),os.kill(pid,9)]
 print(f"[ush] WS server running on :{p}")
 async with websockets.serve(h,"0.0.0.0",p,ping_interval=20,ping_timeout=20): await asyncio.Future()

if __name__=="__main__":
 p=argparse.ArgumentParser(description="ush.py v3.1 (WebSockets)")
 p.add_argument("--server","-s",action="store_true");p.add_argument("-p",type=int,default=8080);p.add_argument("-d",action="store_true");p.add_argument("-v","--verbose",action="store_true");p.add_argument("host",nargs="?");a=p.parse_args()
 if a.host and "-p" not in sys.argv:
  try: ipaddress.ip_address(a.host)
  except: a.p=80
 try:
  asyncio.run(run_s(a.p,a.d) if a.server else run_c(a.host,a.p,a.verbose) if a.host else p.print_help())
 except KeyboardInterrupt: print("Connection Closed.")
