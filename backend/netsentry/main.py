from contextlib import asynccontextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import os
import time
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_
from .models import Event, Alert, ImportRecord, Incident, IncidentAudit, SessionLocal, DemoSessionLocal, init_db, reset_demo_db
from .ingest import parse_upload, MAX_BYTES
from .zeek import parse_zeek
from .detection import detect
from .correlation import correlate

@asynccontextmanager
async def lifespan(app):
    init_db()
    yield

app=FastAPI(title='NetSentry API',version='2.0.0',lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173','http://localhost:8080'],allow_methods=['*'],allow_headers=['*'])

def iso(value):
    if value is None:return None
    if value.tzinfo is None:value=value.replace(tzinfo=timezone.utc)
    return value.isoformat()

def event_json(e):
    keys=['id','source_ip','destination_ip','source_port','destination_port','protocol','duration','connection_uid','hostname','query','source_format','raw_event','event_type','username','bytes_transferred','details']
    return {'timestamp':iso(e.timestamp),**{k:getattr(e,k) for k in keys}}

def alert_json(a):
    keys=['id','source_ip','rule','severity','title','evidence','attack','investigation_steps','status','note','event_ids']
    return {'timestamp':iso(a.timestamp),**{k:getattr(a,k) for k in keys}}

def incident_json(i):
    keys=['id','title','source_ip','severity','confidence','severity_reason','stages','event_ids','alert_ids','status','assigned_to','note']
    return {'timestamp':iso(i.timestamp),**{k:getattr(i,k) for k in keys}}

def audit_json(a):return {'id':a.id,'incident_id':a.incident_id,'timestamp':iso(a.timestamp),'actor':a.actor,'action':a.action,'details':a.details}

def session_for(dataset):
    if dataset == 'main': return SessionLocal
    if dataset == 'demo': return DemoSessionLocal
    raise HTTPException(422, 'dataset must be main or demo')

def persist_import(data,rows,kind,dataset='main'):
    digest=sha256(kind.encode()+b'\x00'+data).hexdigest()
    started=time.perf_counter()
    affected_sources={row.source_ip for row in rows}
    with session_for(dataset)() as db:
        if db.scalar(select(ImportRecord.id).where(ImportRecord.sha256==digest)):
            return {'events_imported':0,'alerts_created':0,'incidents_created':0,'already_imported':True}
        for row in rows:db.add(Event(**row.model_dump()))
        db.flush();db.expire_all()
        all_events=db.scalars(select(Event).where(Event.source_ip.in_(affected_sources)).order_by(Event.timestamp,Event.id)).all()
        detection_start=time.perf_counter()
        findings=detect(all_events)
        detection_ms=round((time.perf_counter()-detection_start)*1000,2)
        new_alerts=0
        for finding in findings:
            existing=db.scalar(select(Alert).where(Alert.fingerprint==finding['fingerprint']))
            if existing:
                old_count=existing.evidence.get('observed',0) if isinstance(existing.evidence,dict) else 0
                new_count=finding['evidence'].get('observed',0) if isinstance(finding['evidence'],dict) else 0
                if new_count>old_count:
                    existing.evidence=finding['evidence'];existing.event_ids=finding['event_ids'];existing.timestamp=finding['timestamp']
            else:
                db.add(Alert(**finding));new_alerts+=1
        db.flush();db.expire_all()
        all_events=db.scalars(select(Event).where(Event.source_ip.in_(affected_sources)).order_by(Event.timestamp,Event.id)).all()
        all_alerts=db.scalars(select(Alert).where(Alert.source_ip.in_(affected_sources)).order_by(Alert.timestamp,Alert.id)).all()
        correlation_start=time.perf_counter()
        correlated=correlate(all_events,all_alerts)
        correlation_ms=round((time.perf_counter()-correlation_start)*1000,2)
        new_incidents=0
        for finding in correlated:
            if not db.scalar(select(Incident.id).where(Incident.fingerprint==finding['fingerprint'])):
                incident=Incident(**finding);db.add(incident);db.flush()
                db.add(IncidentAudit(incident_id=incident.id,actor='system',action='created',details='Multi-stage correlation created incident.'))
                new_incidents+=1
        db.add(ImportRecord(sha256=digest));db.commit()
        return {'events_imported':len(rows),'alerts_created':new_alerts,'incidents_created':new_incidents,'already_imported':False,
            'processing_ms':round((time.perf_counter()-started)*1000,2),'detection_ms':detection_ms,'correlation_ms':correlation_ms}

@app.get('/api/health')
def health():return {'status':'ok','version':'2.0.0'}

@app.get('/api/ready')
def ready(dataset:str='main'):
    with session_for(dataset)() as db:db.execute(select(func.count(Event.id))).scalar_one()
    return {'status':'ready'}

@app.post('/api/ingest')
async def ingest(file:UploadFile=File(...),dataset:str='main'):
    data=await file.read(MAX_BYTES+1)
    return persist_import(data,parse_upload(file.filename or '',data),'generic',dataset)

@app.post('/api/ingest/zeek/{log_type}')
async def ingest_zeek(log_type:str,file:UploadFile=File(...),dataset:str='main'):
    data=await file.read(MAX_BYTES+1)
    return persist_import(data,parse_zeek(log_type,data,file.filename or ''),f'zeek_{log_type}',dataset)

@app.get('/api/overview')
def overview(dataset:str='main'):
    with session_for(dataset)() as db:
        severities={s:n for s,n in db.execute(select(Alert.severity,func.count(Alert.id)).group_by(Alert.severity))}
        types={s:n for s,n in db.execute(select(Event.event_type,func.count(Event.id)).group_by(Event.event_type))}
        sources=[{'source_ip':ip,'events':n} for ip,n in db.execute(select(Event.source_ip,func.count(Event.id)).group_by(Event.source_ip).order_by(func.count(Event.id).desc()).limit(8))]
        return {'events':db.scalar(select(func.count(Event.id))) or 0,'alerts':db.scalar(select(func.count(Alert.id))) or 0,
            'incidents':db.scalar(select(func.count(Incident.id))) or 0,'unique_sources':db.scalar(select(func.count(func.distinct(Event.source_ip)))) or 0,
            'severities':severities,'event_types':types,'top_sources':sources}

@app.get('/api/events')
def events(limit:int=100,source_ip:str|None=None,destination_ip:str|None=None,event_type:str|None=None,username:str|None=None,q:str|None=None,dataset:str='main'):
    if not 1<=limit<=500:raise HTTPException(422,'limit must be 1 to 500')
    query=select(Event)
    if source_ip:query=query.where(Event.source_ip==source_ip)
    if destination_ip:query=query.where(Event.destination_ip==destination_ip)
    if event_type:query=query.where(Event.event_type==event_type)
    if username:query=query.where(Event.username==username)
    if q:
        if len(q)>100:raise HTTPException(422,'Search text must be at most 100 characters')
        term=f'%{q}%';query=query.where(or_(Event.source_ip.like(term),Event.destination_ip.like(term),Event.username.like(term),Event.hostname.like(term),Event.query.like(term),Event.details.like(term)))
    with session_for(dataset)() as db:return [event_json(e) for e in db.scalars(query.order_by(Event.timestamp.desc()).limit(limit))]

@app.get('/api/alerts')
def alerts(severity:str|None=None,rule:str|None=None,status:str|None=None,dataset:str='main'):
    query=select(Alert)
    if severity:query=query.where(Alert.severity==severity)
    if rule:query=query.where(Alert.rule==rule)
    if status:query=query.where(Alert.status==status)
    with session_for(dataset)() as db:return [alert_json(a) for a in db.scalars(query.order_by(Alert.timestamp.desc()).limit(500))]

@app.get('/api/alerts/{alert_id}')
def alert_detail(alert_id:int,dataset:str='main'):
    with session_for(dataset)() as db:
        a=db.get(Alert,alert_id)
        if not a:raise HTTPException(404,'Alert not found')
        related=db.scalars(select(Event).where(Event.id.in_(a.event_ids)).order_by(Event.timestamp)).all()
        return {'alert':alert_json(a),'timeline':[event_json(e) for e in related]}

class AlertUpdate(BaseModel):
    status:str=Field(pattern='^(new|investigating|closed)$')
    note:str=Field(default='',max_length=3000)

@app.patch('/api/alerts/{alert_id}')
def update_alert(alert_id:int,body:AlertUpdate,dataset:str='main'):
    with session_for(dataset)() as db:
        a=db.get(Alert,alert_id)
        if not a:raise HTTPException(404,'Alert not found')
        a.status=body.status;a.note=body.note;db.commit();db.refresh(a)
        return alert_json(a)

@app.get('/api/incidents')
def incidents(status:str|None=None,dataset:str='main'):
    query=select(Incident)
    if status:query=query.where(Incident.status==status)
    with session_for(dataset)() as db:return [incident_json(i) for i in db.scalars(query.order_by(Incident.timestamp.desc()).limit(500))]

@app.get('/api/incidents/{incident_id}')
def incident_detail(incident_id:int,dataset:str='main'):
    with session_for(dataset)() as db:
        i=db.get(Incident,incident_id)
        if not i:raise HTTPException(404,'Incident not found')
        timeline=db.scalars(select(Event).where(Event.id.in_(i.event_ids)).order_by(Event.timestamp)).all()
        related=db.scalars(select(Alert).where(Alert.id.in_(i.alert_ids))).all()
        audit=db.scalars(select(IncidentAudit).where(IncidentAudit.incident_id==incident_id).order_by(IncidentAudit.timestamp,IncidentAudit.id)).all()
        return {'incident':incident_json(i),'timeline':[event_json(e) for e in timeline],'alerts':[alert_json(a) for a in related],'audit':[audit_json(a) for a in audit]}

class IncidentUpdate(BaseModel):
    status:str=Field(pattern='^(open|investigating|contained|resolved)$')
    assigned_to:str=Field(default='',max_length=100)
    note:str=Field(default='',max_length=3000)
    actor:str=Field(default='local analyst',max_length=100)

@app.patch('/api/incidents/{incident_id}')
def update_incident(incident_id:int,body:IncidentUpdate,dataset:str='main'):
    with session_for(dataset)() as db:
        i=db.get(Incident,incident_id)
        if not i:raise HTTPException(404,'Incident not found')
        previous=(i.status,i.assigned_to,i.note)
        i.status=body.status;i.assigned_to=body.assigned_to;i.note=body.note
        db.add(IncidentAudit(incident_id=i.id,actor=body.actor,action='updated',details=f'Status {previous[0]} -> {i.status}; assignee {previous[1]} -> {i.assigned_to}; note updated: {previous[2]!=i.note}'))
        db.commit();db.refresh(i);return incident_json(i)

class ResponseAction(BaseModel):
    action:str=Field(pattern='^(simulate_block_ip|simulate_isolate_host|simulate_reset_credentials)$')
    rationale:str=Field(min_length=3,max_length=1000)
    actor:str=Field(default='local analyst',max_length=100)

@app.post('/api/incidents/{incident_id}/actions')
def response_action(incident_id:int,body:ResponseAction,dataset:str='main'):
    with session_for(dataset)() as db:
        if not db.get(Incident,incident_id):raise HTTPException(404,'Incident not found')
        audit=IncidentAudit(incident_id=incident_id,actor=body.actor,action=body.action,details=f'SIMULATED ONLY: {body.rationale}')
        db.add(audit);db.commit();db.refresh(audit);return audit_json(audit)

@app.get('/api/incidents/{incident_id}/export')
def export_incident(incident_id:int,dataset:str='main'):
    report=incident_detail(incident_id,dataset)
    return JSONResponse(report,headers={'Content-Disposition':f'attachment; filename="netsentry-incident-{incident_id}.json"'})

@app.get('/api/assets')
def assets(dataset:str='main'):
    with session_for(dataset)() as db:
        all_events=db.scalars(select(Event).order_by(Event.timestamp)).all()
        all_alerts=db.scalars(select(Alert)).all()
    records={}
    for e in all_events:
        for ip in (e.source_ip,e.destination_ip):
            if not ip:continue
            record=records.setdefault(ip,{'ip':ip,'hostname':None,'device_type':'observed host','first_seen':iso(e.timestamp),'last_seen':iso(e.timestamp),'connections':0,'alerts':0,'risk_score':0})
            record['last_seen']=iso(e.timestamp)
            # HTTP Host and TLS SNI identify remote services, not the source asset.
            if e.event_type in ('connection','zeek_conn') and (ip==e.source_ip or ip==e.destination_ip):record['connections']+=1
    severity_points={'critical':40,'high':20,'medium':10,'low':5}
    for a in all_alerts:
        if a.source_ip in records:
            record=records[a.source_ip];record['alerts']+=1;record['risk_score']=min(100,record['risk_score']+severity_points.get(a.severity,0))
    return sorted(records.values(),key=lambda x:(-x['risk_score'],x['ip']))

@app.get('/api/assets/{ip}/events')
def asset_events(ip:str,dataset:str='main'):
    with session_for(dataset)() as db:
        found=db.scalars(select(Event).where(or_(Event.source_ip==ip,Event.destination_ip==ip)).order_by(Event.timestamp.desc()).limit(500)).all()
    if not found:raise HTTPException(404,'Asset not found')
    return [event_json(e) for e in found]

@app.get('/api/evaluation')
def evaluation():
    from scripts.evaluate import evaluate
    return evaluate()


@app.post('/api/demo/run')
def run_demo():
    # All writes below use the isolated demo database and the regular parsers.
    sample_dir=Path(os.getenv('NETSENTRY_SAMPLES_PATH',str(Path(__file__).resolve().parents[2]/'samples')))
    inputs=[('conn','zeek_conn.log'),('dns','zeek_dns.log'),('http','zeek_http.log'),('ssl','zeek_ssl.log'),('generic','staged_auth.json')]
    parse_start=time.perf_counter()
    prepared=[]
    for kind,name in inputs:
        data=(sample_dir/name).read_bytes()
        rows=parse_upload(name,data) if kind=='generic' else parse_zeek(kind,data,name)
        prepared.append((kind,data,rows))
    parse_ms=round((time.perf_counter()-parse_start)*1000,2)
    reset_demo_db()
    start=time.perf_counter();results=[]
    for kind,data,rows in prepared:
        results.append(persist_import(data,rows,'generic' if kind=='generic' else f'zeek_{kind}','demo'))
    elapsed_ms=round((time.perf_counter()-start)*1000,2)
    with DemoSessionLocal() as db:
        incident_ids=db.scalars(select(Incident.id)).all()
        rules=sorted(set(db.scalars(select(Alert.rule)).all()))
    return {'dataset':'demo','synthetic':True,'events_imported':sum(r['events_imported'] for r in results),
        'alerts_created':sum(r['alerts_created'] for r in results),'incidents_created':sum(r['incidents_created'] for r in results),
        'incident_ids':incident_ids,'rules':rules,'parse_ms':parse_ms,'processing_ms':elapsed_ms,
        'detection_ms':round(sum(r['detection_ms'] for r in results),2),'correlation_ms':round(sum(r['correlation_ms'] for r in results),2)}
