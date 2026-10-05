import subprocess,socket,time,urllib.request,json,os,pathlib
s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
p=subprocess.Popen(['node',str(pathlib.Path('scripts/mock-api-server.mjs').resolve()),'--port',str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
healthy=False
try:
    deadline=time.monotonic()+20
    while time.monotonic()<deadline and p.poll() is None:
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/__admin/health',timeout=1) as r:
                healthy=r.status==200
                if healthy:break
        except Exception:pass
        time.sleep(.1)
finally:
    ended=p.poll()
    if ended is None:p.terminate()
    stdout,stderr=p.communicate(timeout=10)
print(json.dumps({'healthy':healthy,'child_exit_before_stop':ended,'stdout':stdout,'stderr':stderr,'node_version':subprocess.check_output(['node','--version'],text=True).strip(),'homes':{k:os.environ.get(k) for k in ('HOME','RUSTUP_HOME','CARGO_HOME')}}))
