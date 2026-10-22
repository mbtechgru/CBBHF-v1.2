import os
import tempfile
from fastapi.testclient import TestClient
from backend import app as module

def test_scope():
    assert module.allowed('a.example.org',['*.example.org'])
    assert not module.allowed('example.org',['*.example.org'])
    assert not module.allowed('evil-example.org',['*.example.org'])
    assert not module.allowed('a.example.org.evil.net',['*.example.org'])

def test_end_to_end(tmp_path,monkeypatch):
    monkeypatch.setattr(module,'DB',tmp_path/'test.db')
    client=TestClient(module.app)
    data={'name':'Example test','program_url':'https://example.org/policy','authorization':'Explicitly authorized test account','scope':['example.org','*.example.org']}
    id=client.post('/api/engagements',json=data).json()['id']
    assert client.post(f'/api/engagements/{id}/assets',json={'host':'outside.org'}).status_code==403
    assert client.post(f'/api/engagements/{id}/recon',json={'tool':'subfinder','confirm_authorized':True}).status_code==403
    assert client.post(f'/api/engagements/{id}/assets',json={'host':'app.example.org'}).status_code==200
    assert client.post(f'/api/engagements/{id}/findings',json={'title':'Example issue','asset':'app.example.org'}).status_code==200
    assert 'Example issue' in client.get(f'/api/engagements/{id}/report').text
    assert client.post(f'/api/engagements/{id}/stop').status_code==200
    assert client.get('/api/health').json()['status']=='ok'

def test_report_escaping(tmp_path,monkeypatch):
    monkeypatch.setattr(module,'DB',tmp_path/'escape.db')
    c=TestClient(module.app)
    id=c.post('/api/engagements',json={'name':'Test','program_url':'https://example.org','authorization':'Authorization statement valid','scope':['example.org']}).json()['id']
    c.post(f'/api/engagements/{id}/findings',json={'title':'<script>alert(1)</script>','asset':'example.org'})
    assert '&lt;script&gt;' in c.get(f'/api/engagements/{id}/report').text

def test_v11_graph_evidence_and_job_controls(tmp_path,monkeypatch):
    import io
    monkeypatch.setattr(module,'DB',tmp_path/'v11.db')
    monkeypatch.setattr(module,'EVIDENCE_DIR',tmp_path/'vault')
    c=TestClient(module.app)
    eid=c.post('/api/engagements',json={'name':'Demo test','program_url':'https://example.org/policy','authorization':'Permission granted for demo','scope':['example.org','*.example.org']}).json()['id']
    assert c.post(f'/api/engagements/{eid}/jobs',json={'tool':'subfinder','confirm_authorized':True}).status_code==403
    c.post(f'/api/engagements/{eid}/assets',json={'host':'app.example.org'})
    graph=c.get(f'/api/engagements/{eid}/graph').json()
    assert any(x['id']=='app.example.org' for x in graph['nodes'])
    up=c.post(f'/api/engagements/{eid}/evidence',files={'file':('proof.txt',b'example-only evidence','text/plain')})
    assert up.status_code==200,up.text
    fid=up.json()['id']
    assert c.get(f'/api/engagements/{eid}/evidence/{fid}').content==b'example-only evidence'
    assert c.post(f'/api/engagements/{eid}/evidence',files={'file':('evil.exe',b'X','application/octet-stream')}).status_code==400
    assert c.get(f'/api/engagements/{eid}/jobs').json()==[]
