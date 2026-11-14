"""API-level verification matrix on an isolated database."""
import os,subprocess,sys,tempfile
from pathlib import Path

SAMPLES=Path(__file__).resolve().parents[2]/'samples'

def test_all_public_workflows():
    code=r'''
import os
from pathlib import Path
from fastapi.testclient import TestClient
from netsentry.main import app
s=Path(os.environ['NETSENTRY_SAMPLES'])
with TestClient(app) as c:
    assert c.get('/api/ready').status_code==200
    csv=(s/'security_events.csv').read_bytes()
    r=c.post('/api/ingest',files={'file':('security_events.csv',csv,'text/csv')})
    assert r.status_code==200 and r.json()['events_imported']==88,r.text
    assert c.post('/api/ingest',files={'file':('security_events.csv',csv,'text/csv')}).json()['already_imported']
    for kind in ('conn','dns','http','ssl'):
        data=(s/f'zeek_{kind}.log').read_bytes()
        r=c.post('/api/ingest/zeek/'+kind,files={'file':(f'zeek_{kind}.log',data,'application/json')})
        assert r.status_code==200,r.text
    auth=(s/'staged_auth.json').read_bytes()
    assert c.post('/api/ingest',files={'file':('staged_auth.json',auth,'application/json')}).status_code==200
    overview=c.get('/api/overview').json();assert overview['events']==129 and overview['incidents']==1,overview
    events=c.get('/api/events?event_type=zeek_ssl').json();assert len(events)==1
    assert events[0]['raw_event']['server_name']=='example.test' and events[0]['source_format']=='zeek_ssl'
    assert len(c.get('/api/events?source_ip=192.0.2.15').json())>=1
    assert len(c.get('/api/events?q=analyst-demo').json())==7
    rules={a['rule'] for a in c.get('/api/alerts').json()}
    assert len(rules)==9,rules
    for alert in c.get('/api/alerts').json():
        assert alert['evidence'] and alert['event_ids'] and alert['attack']['technique_id']
        assert c.get(f"/api/alerts/{alert['id']}").json()['timeline']
    incident=c.get('/api/incidents').json()[0]
    assert len(incident['stages'])==4
    iid=incident['id']
    assert c.get(f'/api/incidents/{iid}').json()['timeline']
    assert c.patch(f'/api/incidents/{iid}',json={'status':'investigating','assigned_to':'analyst','note':'Verified evidence'}).json()['assigned_to']=='analyst'
    assert c.post(f'/api/incidents/{iid}/actions',json={'action':'simulate_block_ip','rationale':'Local test only'}).status_code==200
    detail=c.get(f'/api/incidents/{iid}').json();assert len(detail['audit'])==3
    assert c.get(f'/api/incidents/{iid}/export').json()['incident']['note']=='Verified evidence'
    assets=c.get('/api/assets').json();assert assets and c.get('/api/assets/192.0.2.15/events').json()
    assert next(a for a in assets if a['ip']=='10.0.0.30')['hostname'] is None
    report=c.get('/api/evaluation').json();assert report['passed_count']==13 and report['failed_count']==0
    assert c.post('/api/ingest',files={'file':('bad.json',b'[{}]','application/json')}).status_code==422
    assert c.post('/api/ingest/zeek/conn',files={'file':('bad.log',b'{"ts":1}\n','application/json')}).status_code==422
'''
    with tempfile.TemporaryDirectory() as folder:
        env={**os.environ,'NETSENTRY_DATABASE_URL':'sqlite:///'+str(Path(folder)/'main.db'),
             'NETSENTRY_DEMO_DATABASE_URL':'sqlite:///'+str(Path(folder)/'demo.db'),'NETSENTRY_SAMPLES':str(SAMPLES)}
        result=subprocess.run([sys.executable,'-c',code],cwd=str(Path(__file__).resolve().parents[1]),env=env,capture_output=True,text=True)
        assert result.returncode==0,result.stdout+'\n'+result.stderr

def test_later_events_strengthen_existing_alert_evidence():
    code=r'''
import json
from fastapi.testclient import TestClient
from netsentry.main import app
with TestClient(app) as c:
    def rows(start,end):
        return [{'timestamp':f'2026-01-01T00:00:{i:02d}Z','source_ip':'192.0.2.15','event_type':'login_failed','username':'admin'} for i in range(start,end)]
    def send(name,data):return c.post('/api/ingest',files={'file':(name,json.dumps(data),'application/json')})
    assert send('first.json',rows(0,10)).status_code==200
    alert=next(a for a in c.get('/api/alerts').json() if a['rule']=='brute_force')
    assert alert['evidence']['observed']==10
    c.patch(f"/api/alerts/{alert['id']}",json={'status':'investigating','note':'Known source'})
    second=send('later.json',rows(10,12)).json()
    assert second['alerts_created']==0,second
    updated=c.get(f"/api/alerts/{alert['id']}").json()['alert']
    assert updated['evidence']['observed']==12 and updated['note']=='Known source',updated
'''
    with tempfile.TemporaryDirectory() as folder:
        env={**os.environ,'NETSENTRY_DATABASE_URL':'sqlite:///'+str(Path(folder)/'main.db'),
             'NETSENTRY_DEMO_DATABASE_URL':'sqlite:///'+str(Path(folder)/'demo.db')}
        result=subprocess.run([sys.executable,'-c',code],cwd=str(Path(__file__).resolve().parents[1]),env=env,capture_output=True,text=True)
        assert result.returncode==0,result.stdout+'\n'+result.stderr
