"""Loopback presentation bridge to the unchanged Earned Authority M1 runtime."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from functools import partial

HERE = Path(__file__).resolve().parent
CANDIDATE_REPO = HERE.parents[1]
DEFAULT_REPO = CANDIDATE_REPO if (CANDIDATE_REPO/'earned_authority/runtime.py').is_file() else Path('/Users/jkershaw/Documents/earned-authority-kit')

def load_runtime(repo):
    sys.path.insert(0, str(repo))
    from earned_authority.runtime import Runtime, ControlledClock, Denied
    return Runtime, ControlledClock, Denied

class Experiment:
    def __init__(self, repo=DEFAULT_REPO):
        self.repo = Path(repo).resolve()
        self.Runtime, self.Clock, self.Denied = load_runtime(self.repo)
        self.lock = threading.RLock()
        self.tmp = None
        self.reset()

    def reset(self):
        if self.tmp:
            self.rt.close()
            self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory(prefix='ea-pythonized-')
        self.rt = self.Runtime(Path(self.tmp.name)/'runtime.sqlite', clock=self.Clock())
        self.version = 'skill-v1'
        self.q = None
        self.command = None
        self.last_result = None
        self.seq = 0
        self.log = []
        self.audit = None
        self.last = {'action':'reset','ok':True,'message':'Fresh disposable LOCAL_FIXTURE. No grant and no mutation.'}

    def close(self):
        self.rt.close(); self.tmp.cleanup()

    def next_id(self, prefix):
        self.seq += 1
        return f'{prefix}-{self.seq}'

    def act(self, name, params=None):
        params = params or {}
        with self.lock:
            try:
                result = self._act(name, params)
                self.last = {'action':name, 'ok':True, 'result':result}
            except self.Denied as exc:
                self.last = {'action':name, 'ok':False, 'reason':exc.reason}
            except (ValueError, KeyError) as exc:
                self.last = {'action':name, 'ok':False, 'reason':str(exc)}
            self.log.append(self.last)
            return self.snapshot()

    def _act(self, name, p):
        if name == 'reset': self.reset(); return {'mode':'LOCAL_FIXTURE'}
        if name == 'shadow':
            kind = p.get('kind','pass')
            if kind not in {'pass','self','unknown','fail'}: raise ValueError('UNKNOWN_SHADOW_CASE')
            return self.rt.shadow(version=self.version, attempt_id=self.next_id('shadow'),
                independent=kind!='self', observer_available=kind!='unknown', actual='model-v1' if kind=='fail' else 'model-v2')
        if name == 'qualify':
            self.q = self.rt.qualify(version=self.version)
            return self.q
        if name == 'grant':
            if not self.q: raise ValueError('QUALIFICATION_MISSING')
            return self.rt.grant(self.q['qualification_id'], policy_allow=p.get('allow',True) is True)
        if name == 'admit':
            resource = 'registry-a/model-b' if p.get('wrong_scope') else 'registry-a/model-a'
            self.command = None
            self.command = self.rt.admit(version=self.version,resource=resource,attempt_id=self.next_id('release'))
            return self.command
        if name == 'commit':
            if not self.command: raise ValueError('ADMISSION_MISSING')
            self.last_result = self.rt.commit(self.command, actual='model-v1' if p.get('wrong_result') else None,
                observer_available=not p.get('unknown_result',False))
            return self.last_result
        if name == 'read': return self.rt.read()
        if name == 'audit':
            if not self.last_result: raise ValueError('EXECUTION_MISSING')
            self.audit = self.rt.audit_evidence(self.last_result['attempt_id'])
            return {'verified':self.audit is True, 'detail':self.audit}
        if name == 'revoke': return self.rt.revoke()
        if name == 'expire': self.rt.clock.advance(300000); return {'now_ms':self.rt.clock.now_ms}
        if name == 'apply':
            if not self.last_result: raise ValueError('EXECUTION_MISSING')
            self.last_result = self.rt.apply_outcome(self.last_result['attempt_id'])
            return self.last_result
        if name == 'read_grant':
            for _ in range(3): self.rt.shadow(skill='read-health',version='read-v1',attempt_id=self.next_id('read-shadow'))
            q = self.rt.qualify('read-health','read-v1','demo-a')
            return self.rt.grant(q['qualification_id'],action='read')
        if name == 'read_skill':
            return self.rt.execute(skill='read-health',version='read-v1',action='read',attempt_id=self.next_id('read'))
        if name == 'hold': return self.rt.reevaluate(state='UNKNOWN')
        if name == 'requalify':
            self.version='skill-v2'
            for _ in range(3): self.rt.shadow(version=self.version,attempt_id=self.next_id('revised-shadow'))
            self.q=self.rt.qualify(version=self.version)
            return self.q
        raise ValueError('UNKNOWN_ACTION')

    def snapshot(self):
        with self.lock:
            authority = self.rt.authority()
            latest_q = self.rt.qualification(self.q['qualification_id']) if self.q else None
            try:
                with self.rt._db(read_only=True) as db:
                    self.rt._check(db, {'agent':'agent-a','skill':'release-model','version':self.version,'context':'demo-a','action':'release','resource':'registry-a/model-a'})
                release_check = {'allowed':True,'reason':'CURRENT_SOURCE_CHECK_PASSED'}
            except self.Denied as exc:
                release_check = {'allowed':False,'reason':exc.reason}
            return {'source':'LOCAL_FIXTURE','version':self.version,'clock_ms':self.rt.clock.now_ms,
                'qualification':latest_q,'authority':authority,'release_check':release_check,'observations':self.rt.observations(),
                'registry':self.rt.read(),'mutations':self.rt.mutation_count,'events':self.rt.events(),
                'admitted':self.command,'execution':self.last_result,'audit':self.audit,
                'last':self.last,'actions':self.log,
                'source_files':['earned_authority/runtime.py','features/qualification.feature','features/authority.feature','features/withdrawal_and_requalification.feature']}

class Handler(SimpleHTTPRequestHandler):
    experiment = None
    def send_json(self, value, status=200):
        body=json.dumps(value).encode(); self.send_response(status)
        self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path=='/api/state': return self.send_json(self.experiment.snapshot())
        allowed = {'/source/roadmap.html':'roadmap.html','/source/docs/BOUNDARIES.md':'docs/BOUNDARIES.md','/source/docs/ROADMAP.md':'docs/ROADMAP.md','/source/reports/readiness.json':'reports/readiness.json'}
        if self.path in allowed:
            f = self.experiment.repo/allowed[self.path]
            body=f.read_bytes(); self.send_response(200); self.send_header('Content-Type','text/html' if f.suffix=='.html' else 'text/plain; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); return
        if self.path=='/api/roadmap':
            body=json.loads((self.experiment.repo/'reports/readiness.json').read_text())
            return self.send_json({'source':'RECORDED_REPOSITORY_REPORT','report':body})
        return super().do_GET()
    def do_POST(self):
        if self.path!='/api/action': return self.send_json({'error':'not found'},404)
        host=self.headers.get('Host','')
        if host not in {f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'}:
            return self.send_json({'error':'invalid host'},403)
        origin=self.headers.get('Origin')
        if origin and origin not in {f'http://127.0.0.1:{self.server.server_port}',f'http://localhost:{self.server.server_port}'}:
            return self.send_json({'error':'invalid origin'},403)
        if self.headers.get('Content-Type','').split(';')[0]!='application/json': return self.send_json({'error':'JSON required'},415)
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=4096: raise ValueError('invalid body size')
            body=json.loads(self.rfile.read(size))
            if not isinstance(body,dict) or not isinstance(body.get('params',{}),dict): raise ValueError('invalid request')
            self.send_json(self.experiment.act(body['action'],body.get('params')))
        except (ValueError,KeyError,json.JSONDecodeError): self.send_json({'error':'invalid action request'},400)
    def log_message(self, *args): pass

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--repo',type=Path,default=DEFAULT_REPO);parser.add_argument('--port',type=int,default=5184)
    args=parser.parse_args(); experiment=Experiment(args.repo); Handler.experiment=experiment
    server=ThreadingHTTPServer(('127.0.0.1',args.port),partial(Handler,directory=str(HERE)))
    print(f'Earned Authority paper theatre: http://127.0.0.1:{args.port} (LOCAL_FIXTURE)',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close(); experiment.close()
