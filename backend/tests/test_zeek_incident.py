import json,os,tempfile
from pathlib import Path
from fastapi import HTTPException
from fastapi.testclient import TestClient
from netsentry.zeek import parse_zeek

SAMPLES=Path(__file__).resolve().parents[2]/'samples'

def test_zeek_normalization_and_rejection():
 rows=parse_zeek('conn',(SAMPLES/'zeek_conn.log').read_bytes())
 assert len(rows)==27
 assert rows[0].source_format=='zeek_conn'
 assert rows[0].raw_event['uid']=='scan-0'
 assert rows[0].timestamp.tzinfo is not None
 for kind in ('dns','http','ssl'):
  rows=parse_zeek(kind,(SAMPLES/f'zeek_{kind}.log').read_bytes())
  assert rows[0].source_format==f'zeek_{kind}'
 try:parse_zeek('conn',b'{"ts": 123}\n')
 except HTTPException as exc:assert exc.status_code==422
 else:assert False,'incomplete row accepted'

def test_staged_incident_workflow():
 # Separate process-style DB to avoid sharing state with other tests.
 import subprocess,sys
 code=r'''
import os,json
from pathlib import Path
from fastapi.testclient import TestClient
from netsentry.main import app
s=Path(os.environ['NETSENTRY_SAMPLES'])
with TestClient(app) as c:
 for kind in ('conn','dns','http','ssl'):
  r=c.post('/api/ingest/zeek/'+kind,files={'file':(f'zeek_{kind}.log',(s/f'zeek_{kind}.log').read_bytes(),'application/json')})
  assert r.status_code==200,r.text
 r=c.post('/api/ingest',files={'file':('staged_auth.json',(s/'staged_auth.json').read_bytes(),'application/json')})
 assert r.status_code==200,r.text
 rules={a['rule'] for a in c.get('/api/alerts').json()}
 assert {'port_scan','dns_anomaly','outbound_transfer','auth_success_after_fail'} <= rules,rules
 incidents=c.get('/api/incidents').json();assert len(incidents)==1,incidents
 i=incidents[0];assert i['severity']=='critical';assert len(i['stages'])==4
 detail=c.get(f"/api/incidents/{i['id']}").json();assert len(detail['timeline'])>=4
 updated=c.patch(f"/api/incidents/{i['id']}",json={'status':'investigating','assigned_to':'demo analyst','note':'Reviewing','actor':'demo analyst'})
 assert updated.status_code==200,updated.text
 action=c.post(f"/api/incidents/{i['id']}/actions",json={'action':'simulate_block_ip','rationale':'Synthetic tabletop response'})
 assert action.status_code==200 and 'SIMULATED ONLY' in action.json()['details']
 assert len(c.get(f"/api/incidents/{i['id']}").json()['audit'])==3
 assert c.get(f"/api/incidents/{i['id']}/export").status_code==200
 assert c.get('/api/assets').json()
 assert c.get('/api/events?q=analyst-demo').json()
'''
 with tempfile.TemporaryDirectory() as folder:
  env={**os.environ,'NETSENTRY_DATABASE_URL':'sqlite:///'+str(Path(folder)/'test.db'),'NETSENTRY_SAMPLES':str(SAMPLES)}
  r=subprocess.run([sys.executable,'-c',code],cwd=str(Path(__file__).resolve().parents[1]),env=env,capture_output=True,text=True)
  assert r.returncode==0,r.stdout+'\n'+r.stderr

def test_official_zeek_conn_example_parses_without_alert():
 from types import SimpleNamespace
 from netsentry.detection import detect
 rows=parse_zeek('conn',(SAMPLES/'zeek_official_conn.log').read_bytes(),filename='zeek_official_conn.log')
 assert len(rows)==2
 assert rows[0].connection_uid=='CMdzit1AMNsmfAIiQc'
 assert rows[1].bytes_transferred==77
 assert detect([SimpleNamespace(id=i+1,**r.model_dump()) for i,r in enumerate(rows)])==[]
