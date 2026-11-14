import json, os, tempfile
from pathlib import Path
# Set the database path before importing the application.
_tmp=tempfile.TemporaryDirectory()
os.environ['NETSENTRY_DATABASE_URL']='sqlite:///'+str(Path(_tmp.name)/'test.db')
from fastapi.testclient import TestClient
from netsentry.main import app

def test_end_to_end():
 with TestClient(app) as c:
  rows=[]
  for i in range(10): rows.append({'timestamp':f'2026-01-01T00:00:{i:02d}+00:00','source_ip':'192.0.2.15','event_type':'login_failed','username':'admin'})
  r=c.post('/api/ingest',files={'file':('events.json',json.dumps(rows),'application/json')})
  assert r.status_code==200,r.text
  assert r.json()['events_imported']==10
  assert c.get('/api/overview').json()['events']==10
  alerts=c.get('/api/alerts').json()
  alert=next(a for a in alerts if a['rule']=='brute_force')
  detail=c.get(f"/api/alerts/{alert['id']}").json()
  assert len(detail['timeline'])==10
  assert detail['alert']['evidence']['threshold']==10
  updated=c.patch(f"/api/alerts/{alert['id']}",json={'status':'investigating','note':'Verified in identity logs'})
  assert updated.json()['note']=='Verified in identity logs'
  assert c.post('/api/ingest',files={'file':('bad.json','[{}]','application/json')}).status_code==422

def test_csv_sample_and_repeated_import():
 from pathlib import Path
 sample=Path(__file__).resolve().parents[2]/'samples/security_events.csv'
 with TestClient(app) as c:
  data=sample.read_bytes()
  r=c.post('/api/ingest',files={'file':('sample.csv',data,'text/csv')})
  assert r.status_code==200,r.text
  assert r.json()['events_imported']==88
  assert {a['rule'] for a in c.get('/api/alerts').json()}=={'brute_force','port_scan','high_traffic','distributed_auth','privilege_escalation','suspicious_ip'}
  assert c.post('/api/ingest',files={'file':('sample.csv',data,'text/csv')}).json()['alerts_created']==0
