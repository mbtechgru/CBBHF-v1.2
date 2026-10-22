import json
from fastapi.testclient import TestClient
from backend import app as module

def test_import_scope_and_review(tmp_path,monkeypatch):
    monkeypatch.setattr(module,'DB',tmp_path/'test.db')
    c=TestClient(module.app)
    eid=c.post('/api/engagements',json={'name':'Sample program','program_url':'https://example.org/policy','authorization':'Written approval for testing','scope':['example.org','*.example.org']}).json()['id']
    records=[{'template-id':'tech-detect','matched-at':'https://app.example.org/path','info':{'name':'Technology detected','severity':'info'}},
             {'template-id':'out-of-scope','matched-at':'https://evil.org/','info':{'name':'Outside','severity':'high'}}]
    payload={'source':'nuclei','payload':'\n'.join(map(json.dumps,records)),'confirm_authorized':True}
    assert c.post(f'/api/engagements/{eid}/imports',json={**payload,'confirm_authorized':False}).status_code==403
    r=c.post(f'/api/engagements/{eid}/imports',json=payload)
    assert r.status_code==200,r.text
    assert len(r.json()['accepted'])==1 and len(r.json()['rejected'])==1
    fid=r.json()['accepted'][0]['id']
    assert c.get(f'/api/engagements/{eid}/findings').json()[0]['status']=='Draft'
    r=c.patch(f'/api/engagements/{eid}/findings/{fid}/review',json={'status':'Validated','analyst_note':'Confirmed on synthetic test account'})
    assert r.status_code==200
    assert c.get(f'/api/engagements/{eid}/findings').json()[0]['status']=='Validated'

def test_zap_burp_import(tmp_path,monkeypatch):
    monkeypatch.setattr(module,'DB',tmp_path/'test2.db')
    c=TestClient(module.app)
    eid=c.post('/api/engagements',json={'name':'Sample program','program_url':'https://example.org/policy','authorization':'Written approval for testing','scope':['example.org','*.example.org']}).json()['id']
    zap={'site':[{'@name':'https://app.example.org','alerts':[{'name':'Missing header','riskdesc':'Low (Medium)','instances':[{'uri':'https://app.example.org/'}]}]}]}
    burp={'issues':[{'name':'Test observation','severity':'Medium','url':'https://app.example.org/test'}]}
    for source,payload in [('zap',json.dumps(zap)),('burp',json.dumps(burp))]:
        r=c.post(f'/api/engagements/{eid}/imports',json={'source':source,'payload':payload,'confirm_authorized':True})
        assert r.status_code==200,r.text
        assert len(r.json()['accepted'])==1
    assert c.post(f'/api/engagements/{eid}/imports',json={'source':'zap','payload':'invalid','confirm_authorized':True}).status_code==400
