import os, subprocess, sys, tempfile
from pathlib import Path

def test_demo_uses_real_pipeline_and_preserves_main():
    code=r'''
from fastapi.testclient import TestClient
from netsentry.main import app
with TestClient(app) as c:
    r=c.post('/api/demo/run');assert r.status_code==200,r.text
    data=r.json();assert data['synthetic'] and data['events_imported']==41
    assert data['incidents_created']==1 and data['alerts_created']>=4
    assert c.get('/api/overview?dataset=main').json()['events']==0
    assert c.get('/api/overview?dataset=demo').json()['events']==41
    incident=c.get('/api/incidents?dataset=demo').json()[0]
    assert len(incident['stages'])==4
    detail=c.get(f"/api/incidents/{incident['id']}?dataset=demo").json()
    assert detail['timeline'] and detail['alerts']
    assert c.get(f"/api/incidents/{incident['id']}/export?dataset=demo").json()['incident']['id']==incident['id']
    r2=c.post('/api/demo/run');assert r2.status_code==200,r2.text
    assert c.get('/api/overview?dataset=demo').json()['events']==41
    assert len(c.get('/api/incidents?dataset=demo').json())==1
    assert c.get('/api/overview?dataset=main').json()['events']==0
'''
    with tempfile.TemporaryDirectory() as folder:
        env={**os.environ,'NETSENTRY_DATABASE_URL':'sqlite:///'+str(Path(folder)/'main.db'),
             'NETSENTRY_DEMO_DATABASE_URL':'sqlite:///'+str(Path(folder)/'demo.db')}
        result=subprocess.run([sys.executable,'-c',code],cwd=str(Path(__file__).resolve().parents[1]),env=env,capture_output=True,text=True)
        assert result.returncode==0,result.stdout+'\n'+result.stderr
