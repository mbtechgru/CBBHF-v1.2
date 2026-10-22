"""CBBHF: local-first, scope-gated bug bounty workflow manager."""
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import uuid
import threading
import signal
import time
import html
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DB = Path(os.environ.get('CBBHF_DB', ROOT / 'cbbhf.sqlite3'))
app = FastAPI(title='CBBHF', version='1.2.0', docs_url='/api/docs')

def now(): return datetime.now(timezone.utc).isoformat()
def conn():
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.executescript('''CREATE TABLE IF NOT EXISTS engagements (id TEXT PRIMARY KEY,name TEXT NOT NULL,program_url TEXT NOT NULL,authorization TEXT NOT NULL,scope TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 0,created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY,engagement_id TEXT NOT NULL,host TEXT NOT NULL,source TEXT NOT NULL,created TEXT NOT NULL,UNIQUE(engagement_id,host),FOREIGN KEY(engagement_id) REFERENCES engagements(id));
    CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY,engagement_id TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,asset TEXT NOT NULL,description TEXT NOT NULL,evidence TEXT NOT NULL,created TEXT NOT NULL,FOREIGN KEY(engagement_id) REFERENCES engagements(id));
    CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,event TEXT NOT NULL,detail TEXT NOT NULL);''')
    c.executescript("""CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY,engagement_id TEXT NOT NULL,tool TEXT NOT NULL,root TEXT NOT NULL,status TEXT NOT NULL,started TEXT NOT NULL,finished TEXT,discovered INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',FOREIGN KEY(engagement_id) REFERENCES engagements(id));
    CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY,engagement_id TEXT NOT NULL,filename TEXT NOT NULL,content_type TEXT NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,created TEXT NOT NULL,FOREIGN KEY(engagement_id) REFERENCES engagements(id));""")
    return c

JOB_LOCK=threading.RLock()
RUNNING={}
EVIDENCE_DIR=Path(os.environ.get('CBBHF_EVIDENCE_DIR',ROOT/'private_evidence'))

def log(c,event,detail): c.execute('INSERT INTO audit(at,event,detail) VALUES(?,?,?)',(now(),event,json.dumps(detail)))

def normalize_host(raw):
    raw=raw.strip().lower()
    if not raw or any(x in raw for x in ('*','/','\\','@',' ','?','#',':')): raise ValueError('Provide a bare DNS hostname, not URL, wildcard or port')
    if len(raw)>253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',raw): raise ValueError('Invalid hostname')
    if '..' in raw: raise ValueError('Invalid hostname')
    try: ipaddress.ip_address(raw); raise ValueError('IP targets not supported in this release')
    except ValueError as e:
        if str(e).startswith('IP targets'): raise
    if '.' not in raw: raise ValueError('Fully qualified hostname required')
    return raw

def allowed(host,scope):
    host=normalize_host(host)
    for entry in scope:
        entry=entry.lower().strip()
        if entry.startswith('*.'):
            base=normalize_host(entry[2:])
            if host.endswith('.'+base): return True
        elif host==normalize_host(entry): return True
    return False

class EngagementIn(BaseModel):
    name:str=Field(min_length=2,max_length=120)
    program_url:str
    authorization:str=Field(min_length=15)
    scope:list[str]=Field(min_length=1)
    active:bool=False
class AssetIn(BaseModel):
    host:str
    source:str='manual'
class FindingIn(BaseModel):
    title:str=Field(min_length=3)
    severity:str='Info'
    status:str='Draft'
    asset:str
    description:str=''
    evidence:str=''
class ReconIn(BaseModel):
    tool:str
    confirm_authorized:bool=False

@app.get('/')
def home(): return FileResponse(ROOT/'frontend'/'index.html')
@app.get('/api/health')
def health(): return {'status':'ok','version':'1.2.0'}
@app.get('/api/engagements')
def engagements():
    with conn() as c: return [dict(r) | {'scope':json.loads(r['scope'])} for r in c.execute('SELECT * FROM engagements ORDER BY created DESC')]
@app.post('/api/engagements')
def create_engagement(v:EngagementIn):
    p=urlparse(v.program_url)
    if p.scheme!='https' or not p.netloc: raise HTTPException(400,'Program URL must be HTTPS')
    if any(not isinstance(x,str) for x in v.scope): raise HTTPException(400,'Invalid scope')
    try:
        for x in v.scope: normalize_host(x[2:] if x.startswith('*.') else x)
    except ValueError as e: raise HTTPException(400,str(e))
    id=str(uuid.uuid4())
    with conn() as c:
        c.execute('INSERT INTO engagements VALUES(?,?,?,?,?,?,?)',(id,v.name,v.program_url,v.authorization,json.dumps(v.scope),int(v.active),now()))
        log(c,'engagement.created',{'id':id,'name':v.name})
    return {'id':id}
@app.post('/api/engagements/{id}/activate')
def activate(id:str):
    with conn() as c:
        r=c.execute('SELECT id FROM engagements WHERE id=?',(id,)).fetchone()
        if not r: raise HTTPException(404,'Not found')
        c.execute('UPDATE engagements SET active=1 WHERE id=?',(id,))
        log(c,'engagement.activated',{'id':id})
    return {'active':True}
@app.post('/api/engagements/{id}/stop')
def stop(id:str):
    with conn() as c:
        if not c.execute('SELECT id FROM engagements WHERE id=?',(id,)).fetchone(): raise HTTPException(404,'Not found')
        c.execute('UPDATE engagements SET active=0 WHERE id=?',(id,))
        log(c,'engagement.stopped',{'id':id})
    cancel_jobs(id)
    return {'active':False}

def engagement(c,id):
    r=c.execute('SELECT * FROM engagements WHERE id=?',(id,)).fetchone()
    if not r: raise HTTPException(404,'Engagement not found')
    return r
@app.get('/api/engagements/{id}/assets')
def assets(id:str):
    with conn() as c:
        engagement(c,id)
        return [dict(x) for x in c.execute('SELECT * FROM assets WHERE engagement_id=? ORDER BY host',(id,))]
@app.post('/api/engagements/{id}/assets')
def add_asset(id:str,v:AssetIn):
    with conn() as c:
        e=engagement(c,id)
        try:
            host=normalize_host(v.host)
            if not allowed(host,json.loads(e['scope'])): raise HTTPException(403,'Target outside scope')
        except ValueError as ex: raise HTTPException(400,str(ex))
        c.execute('INSERT OR IGNORE INTO assets VALUES(?,?,?,?,?)',(str(uuid.uuid4()),id,host,v.source[:80],now()))
        log(c,'asset.added',{'engagement':id,'host':host})
    return {'host':host}
@app.get('/api/engagements/{id}/findings')
def findings(id:str):
    with conn() as c:
        engagement(c,id)
        return [dict(x) for x in c.execute('SELECT * FROM findings WHERE engagement_id=? ORDER BY created DESC',(id,))]
@app.post('/api/engagements/{id}/findings')
def add_finding(id:str,v:FindingIn):
    if v.severity not in ('Critical','High','Medium','Low','Info') or v.status not in ('Draft','Validated','Submitted','Resolved'): raise HTTPException(400,'Invalid severity/status')
    with conn() as c:
        e=engagement(c,id)
        try:
            host=normalize_host(v.asset)
            if not allowed(host,json.loads(e['scope'])): raise HTTPException(403,'Asset outside scope')
        except ValueError as ex: raise HTTPException(400,str(ex))
        fid=str(uuid.uuid4())
        c.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?)',(fid,id,v.title,v.severity,v.status,host,v.description,v.evidence,now()))
        log(c,'finding.created',{'engagement':id,'finding':fid})
    return {'id':fid}
@app.get('/api/engagements/{id}/report',response_class=HTMLResponse)
def report(id:str):
    from html import escape as h
    with conn() as c:
        e=engagement(c,id)
        rows=c.execute('SELECT * FROM findings WHERE engagement_id=?',(id,)).fetchall()
    body=''.join(f'<article><h2>{h(r["title"])}</h2><p><b>{h(r["severity"])} · {h(r["status"])}</b> — {h(r["asset"])}</p><h3>Description</h3><pre>{h(r["description"])}</pre><h3>Evidence</h3><pre>{h(r["evidence"])}</pre></article>' for r in rows)
    return f'<!doctype html><html><meta charset="utf-8"><title>CBBHF Report</title><style>body{{font:16px system-ui;max-width:900px;margin:50px auto;color:#19334a}}article{{border:1px solid #ddd;border-radius:12px;padding:20px;margin:20px 0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}@media print{{article{{break-inside:avoid}}}}</style><h1>{h(e["name"])} — Findings</h1><p>Generated {h(now())} · Authorized engagement report</p>{body or "<p>No findings yet.</p>"}</html>'
@app.get('/api/audit')
def audit():
    with conn() as c: return [dict(r) for r in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]
@app.get('/api/tools')
def tools(): return {t:bool(shutil.which(t)) for t in ('subfinder','amass','httpx','spiderfoot')}
@app.post('/api/engagements/{id}/recon')
def recon(id:str,v:ReconIn):
    # Deliberately passive only: no port scanning, HTTP probing, or automatic execution.
    if v.tool not in ('subfinder','amass'): raise HTTPException(400,'Only passive subfinder/amass supported')
    if not v.confirm_authorized: raise HTTPException(403,'Explicit authorization confirmation required')
    with conn() as c:
        e=engagement(c,id)
        if not e['active']: raise HTTPException(403,'Engagement is stopped')
        scope=json.loads(e['scope'])
        roots=[s for s in scope if not s.startswith('*.')]
        if len(roots)!=1 or any(s!='*.'+roots[0] and s!=roots[0] for s in scope):
            raise HTTPException(400,'Passive recon requires one explicit root domain and optional matching wildcard')
        root=roots[0]
        if not shutil.which(v.tool): raise HTTPException(400,f'{v.tool} not installed')
        cmd=[v.tool,'-d',root,'-silent'] if v.tool=='subfinder' else ['amass','enum','-passive','-d',root]
        log(c,'recon.started',{'engagement':id,'tool':v.tool,'domain':root})
    try:
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=90,check=False)
    except subprocess.TimeoutExpired: raise HTTPException(504,'Tool exceeded 90-second limit')
    hosts=set()
    for line in result.stdout.splitlines()[:5000]:
        try:
            host=normalize_host(line)
            if allowed(host,scope): hosts.add(host)
        except ValueError: continue
    with conn() as c:
        for host in hosts:
            c.execute('INSERT OR IGNORE INTO assets VALUES(?,?,?,?,?)',(str(uuid.uuid4()),id,host,v.tool,now()))
        log(c,'recon.completed',{'engagement':id,'tool':v.tool,'count':len(hosts),'returncode':result.returncode})
    return {'tool':v.tool,'discovered':len(hosts),'hosts':sorted(hosts),'exit_code':result.returncode,'stderr':result.stderr[:400]}

# v1.1 asynchronous passive reconnaissance with bounded subprocesses and cancellation.
def cancel_jobs(engagement_id):
    with JOB_LOCK:
        for jid, item in list(RUNNING.items()):
            if item['engagement_id']==engagement_id:
                item['cancel'].set()
                proc=item.get('proc')
                if proc is not None and proc.poll() is None:
                    try: proc.terminate()
                    except ProcessLookupError: pass

def execute_job(jid,engagement_id,tool,root,scope):
    cmd=[tool,'-d',root,'-silent'] if tool=='subfinder' else ['amass','enum','-passive','-d',root]
    with JOB_LOCK: state=RUNNING[jid]
    status='failed'; error=''; hosts=set()
    try:
        if state['cancel'].is_set():
            status='cancelled'
        else:
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            with JOB_LOCK:
                state['proc']=proc
                if state['cancel'].is_set(): proc.terminate()
            try: out,err=proc.communicate(timeout=90)
            except subprocess.TimeoutExpired:
                proc.kill();proc.communicate();raise TimeoutError('Passive tool timed out after 90 seconds')
            if state['cancel'].is_set(): status='cancelled'
            elif proc.returncode != 0: error=(err or 'Tool failed')[:400];status='failed'
            else:
                for line in out.splitlines()[:5000]:
                    try:
                        host=normalize_host(line)
                        if allowed(host,scope): hosts.add(host)
                    except ValueError: pass
                status='completed'
    except Exception as ex: error=str(ex)[:400]
    with JOB_LOCK:
        with conn() as c:
            e=engagement(c,engagement_id)
            if not e['active'] or state['cancel'].is_set(): status='cancelled'
            if status=='completed':
                for host in hosts:
                    c.execute('INSERT OR IGNORE INTO assets VALUES(?,?,?,?,?)',(str(uuid.uuid4()),engagement_id,host,tool,now()))
            c.execute('UPDATE jobs SET status=?,finished=?,discovered=?,error=? WHERE id=?',(status,now(),len(hosts) if status=='completed' else 0,error,jid))
            log(c,'recon.job.finished',{'job':jid,'status':status,'discovered':len(hosts) if status=='completed' else 0})
        RUNNING.pop(jid,None)

@app.post('/api/engagements/{id}/jobs')
def start_job(id:str,v:ReconIn):
    if v.tool not in ('subfinder','amass'): raise HTTPException(400,'Only passive discovery tools are supported')
    if not v.confirm_authorized: raise HTTPException(403,'Authorization confirmation required')
    with JOB_LOCK:
        with conn() as c:
            e=engagement(c,id)
            if not e['active']: raise HTTPException(403,'Engagement stopped')
            scope=json.loads(e['scope'])
            roots=[s for s in scope if not s.startswith('*.')]
            if len(roots)!=1 or any(s not in (roots[0],'*.'+roots[0]) for s in scope):
                raise HTTPException(400,'One explicit root and optional matching wildcard required')
            if not shutil.which(v.tool): raise HTTPException(400,f'{v.tool} is not installed')
            if any(x['engagement_id']==id for x in RUNNING.values()): raise HTTPException(409,'An engagement job is already running')
            jid=str(uuid.uuid4());root=roots[0]
            c.execute('INSERT INTO jobs(id,engagement_id,tool,root,status,started) VALUES(?,?,?,?,?,?)',(jid,id,v.tool,root,'running',now()))
            log(c,'recon.job.started',{'job':jid,'engagement':id,'tool':v.tool})
        RUNNING[jid]={'engagement_id':id,'cancel':threading.Event(),'proc':None}
        threading.Thread(target=execute_job,args=(jid,id,v.tool,root,scope),daemon=True).start()
    return {'job_id':jid,'status':'running'}

@app.get('/api/engagements/{id}/jobs')
def list_jobs(id:str):
    with conn() as c:
        engagement(c,id)
        return [dict(r) for r in c.execute('SELECT * FROM jobs WHERE engagement_id=? ORDER BY started DESC LIMIT 50',(id,))]

@app.post('/api/engagements/{id}/jobs/{jid}/cancel')
def cancel_job(id:str,jid:str):
    with conn() as c:
        engagement(c,id)
        if not c.execute('SELECT 1 FROM jobs WHERE id=? AND engagement_id=?',(jid,id)).fetchone(): raise HTTPException(404,'Job not found')
    with JOB_LOCK:
        item=RUNNING.get(jid)
        if item and item['engagement_id']==id:
            item['cancel'].set()
            proc=item.get('proc')
            if proc is not None and proc.poll() is None: proc.terminate()
    return {'cancel_requested':bool(item)}

@app.get('/api/engagements/{id}/graph')
def graph(id:str):
    with conn() as c:
        e=engagement(c,id)
        assets=[dict(r) for r in c.execute('SELECT * FROM assets WHERE engagement_id=? ORDER BY host',(id,))]
        findings=[dict(r) for r in c.execute('SELECT * FROM findings WHERE engagement_id=?',(id,))]
    # Local-only asset relationships, no DNS lookups or probes.
    nodes=[{'id':'engagement','label':e['name'],'type':'engagement'}]
    edges=[]
    for a in assets[:500]:
        nodes.append({'id':a['host'],'label':a['host'],'type':'asset'})
        edges.append({'source':'engagement','target':a['host']})
    hosts={a['host'] for a in assets[:500]}
    for f in findings[:500]:
        if f['asset'] in hosts:
            nodes.append({'id':f['id'],'label':f['title'],'type':'finding','severity':f['severity']})
            edges.append({'source':f['asset'],'target':f['id']})
    return {'nodes':nodes,'edges':edges}

# Evidence uploads are explicitly limited to non-executable, non-archive formats.
ALLOWED_EVIDENCE={'.txt':'text/plain','.md':'text/markdown','.json':'application/json','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.pdf':'application/pdf'}
MAX_EVIDENCE=5*1024*1024
@app.post('/api/engagements/{id}/evidence')
async def upload_evidence(id:str,file:UploadFile=File(...)):
    import hashlib
    with conn() as c: engagement(c,id)
    name=Path(file.filename or '').name
    suffix=Path(name).suffix.lower()
    if suffix not in ALLOWED_EVIDENCE or name in ('','.','..'): raise HTTPException(400,'Unsupported evidence format')
    data=await file.read(MAX_EVIDENCE+1)
    if len(data)>MAX_EVIDENCE: raise HTTPException(413,'Evidence exceeds 5 MiB')
    if suffix=='.png' and not data.startswith(b'\x89PNG\r\n\x1a\n'): raise HTTPException(400,'Invalid PNG')
    if suffix in ('.jpg','.jpeg') and not data.startswith(b'\xff\xd8\xff'): raise HTTPException(400,'Invalid JPEG')
    if suffix=='.pdf' and not data.startswith(b'%PDF-'): raise HTTPException(400,'Invalid PDF')
    if suffix in ('.txt','.md','.json'):
        try: data.decode('utf-8')
        except UnicodeDecodeError: raise HTTPException(400,'Text evidence must be UTF-8')
    EVIDENCE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    eid=str(uuid.uuid4());dest=EVIDENCE_DIR/eid
    with dest.open('xb') as f: f.write(data)
    dest.chmod(0o600)
    with conn() as c:
        c.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)',(eid,id,name,ALLOWED_EVIDENCE[suffix],len(data),hashlib.sha256(data).hexdigest(),now()))
        log(c,'evidence.uploaded',{'engagement':id,'evidence':eid,'size':len(data)})
    return {'id':eid,'filename':name,'sha256':hashlib.sha256(data).hexdigest()}

@app.get('/api/engagements/{id}/evidence')
def list_evidence(id:str):
    with conn() as c:
        engagement(c,id)
        return [dict(r) for r in c.execute('SELECT * FROM evidence WHERE engagement_id=? ORDER BY created DESC',(id,))]

@app.get('/api/engagements/{id}/evidence/{eid}')
def download_evidence(id:str,eid:str):
    with conn() as c:
        engagement(c,id)
        r=c.execute('SELECT * FROM evidence WHERE id=? AND engagement_id=?',(eid,id)).fetchone()
    if not r: raise HTTPException(404,'Evidence not found')
    path=EVIDENCE_DIR/eid
    if not path.is_file(): raise HTTPException(404,'Evidence file missing')
    return FileResponse(path,media_type='application/octet-stream',filename=r['filename'],content_disposition_type='attachment',headers={'X-Content-Type-Options':'nosniff','Cache-Control':'no-store'})


# v1.2: OFFLINE import of JSON/JSONL exports from Nuclei, OWASP ZAP, and
# Burp Suite. Importing does not contact the assessed target or execute a scanner.
IMPORT_MAX_BYTES = 2 * 1024 * 1024
IMPORT_MAX_RECORDS = 500
class ImportIn(BaseModel):
    source: str
    payload: str = Field(max_length=IMPORT_MAX_BYTES)
    confirm_authorized: bool = False

class ReviewIn(BaseModel):
    status: str
    analyst_note: str = Field(default='', max_length=4000)


def source_records(source, payload):
    if source == 'nuclei':
        records = [json.loads(line) for line in payload.splitlines() if line.strip()]
    elif source == 'zap':
        data = json.loads(payload)
        # OWASP ZAP traditional JSON report: site[].alerts[]
        records = [a | {'_site': site.get('@name', '')}
                   for site in data.get('site', []) for a in site.get('alerts', [])]
    elif source == 'burp':
        # JSON export from Burp extensions or normalized Burp issue export.
        # Native Burp XML is intentionally not accepted as JSON.
        data = json.loads(payload)
        records = data.get('issues', []) if isinstance(data, dict) else data
    else:
        raise ValueError('Supported sources: nuclei, zap, burp')
    if not isinstance(records, list) or len(records) > IMPORT_MAX_RECORDS:
        raise ValueError('Expected a list with at most 500 findings')
    if not all(isinstance(r, dict) for r in records):
        raise ValueError('Every finding must be a JSON object')
    return records


def record_fields(source, record):
    if source == 'nuclei':
        info = record.get('info') or {}
        return (info.get('name') or record.get('template-id') or 'Nuclei observation',
                info.get('severity') or 'info', record.get('matched-at') or record.get('host') or '',
                info.get('description') or '', record.get('template-id') or '')
    if source == 'zap':
        return (record.get('name') or record.get('alert') or 'ZAP observation',
                record.get('riskdesc') or record.get('risk') or 'info',
                (record.get('instances') or [{}])[0].get('uri', '') if record.get('instances') else record.get('_site', ''),
                record.get('desc') or '', record.get('pluginid') or '')
    return (record.get('name') or record.get('title') or 'Burp observation',
            record.get('severity') or 'info', record.get('url') or record.get('host') or '',
            record.get('description') or record.get('detail') or '', record.get('type') or '')


def host_from_observation(raw):
    if not isinstance(raw, str): raise ValueError('Missing URL or hostname')
    p = urlparse(raw)
    if p.scheme:
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.password:
            raise ValueError('Unsupported URL')
        return normalize_host(p.hostname)
    return normalize_host(raw)


def severity_from_observation(raw):
    text = str(raw).strip().lower()
    for level in ('critical','high','medium','low','info','informational'):
        if text.startswith(level): return 'Info' if level == 'informational' else level.capitalize()
    return 'Info'


@app.post('/api/engagements/{id}/imports')
def import_observations(id: str, v: ImportIn):
    if not v.confirm_authorized: raise HTTPException(403,'Authorization confirmation required')
    if len(v.payload.encode('utf-8')) > IMPORT_MAX_BYTES:
        raise HTTPException(413,'Import exceeds 2 MiB')
    try: records = source_records(v.source, v.payload)
    except (ValueError, TypeError, json.JSONDecodeError) as ex:
        raise HTTPException(400, f'Invalid import: {str(ex)[:160]}')
    accepted=[]; rejected=[]
    with conn() as c:
        e=engagement(c,id)
        scope=json.loads(e['scope'])
        # Imports may be reviewed when stopped; they do not run any active testing.
        for index,r in enumerate(records):
            try:
                title,sev,url,description,signature=record_fields(v.source,r)
                host=host_from_observation(url)
                if not allowed(host,scope): raise ValueError('Outside engagement scope')
                title=str(title)[:240]
                if not title.strip(): raise ValueError('Empty title')
                fid=str(uuid.uuid4())
                evidence=json.dumps({'source':v.source,'signature':str(signature)[:120],
                                     'original_url':str(url)[:500]},ensure_ascii=False)
                c.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?)',
                          (fid,id,title,severity_from_observation(sev),'Draft',host,
                           str(description)[:4000],evidence,now()))
                accepted.append({'id':fid,'asset':host,'title':title})
            except (ValueError, TypeError, AttributeError) as ex:
                rejected.append({'index':index,'reason':str(ex)[:120]})
        log(c,'observations.imported',{'engagement':id,'source':v.source,
                                      'accepted':len(accepted),'rejected':len(rejected)})
    return {'source':v.source,'accepted':accepted,'rejected':rejected,
            'message':'Imported findings are Draft and require manual validation.'}


@app.patch('/api/engagements/{id}/findings/{fid}/review')
def review_finding(id: str, fid: str, v: ReviewIn):
    if v.status not in ('Draft','Validated','Submitted','Resolved'):
        raise HTTPException(400,'Invalid review status')
    with conn() as c:
        engagement(c,id)
        row=c.execute('SELECT * FROM findings WHERE id=? AND engagement_id=?',(fid,id)).fetchone()
        if not row: raise HTTPException(404,'Finding not found')
        # Explicit analyst action required; scanner results never auto-validate.
        note='\n[Analyst review '+now()+'] '+v.analyst_note if v.analyst_note else ''
        c.execute('UPDATE findings SET status=?, evidence=? WHERE id=?',
                  (v.status,row['evidence']+note,fid))
        log(c,'finding.reviewed',{'engagement':id,'finding':fid,'status':v.status})
    return {'id':fid,'status':v.status}
