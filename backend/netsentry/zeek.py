"""Normalize offline Zeek JSON logs. No live capture or packet processing."""
import json
from datetime import datetime, timezone
from fastapi import HTTPException
from pydantic import ValidationError
from .normalize import EventInput
from .ingest import MAX_BYTES, MAX_ROWS

SUPPORTED={'conn','dns','http','ssl'}

def parse_zeek(log_type:str,data:bytes,filename:str|None=None):
    if log_type not in SUPPORTED: raise HTTPException(400,'log_type must be conn, dns, http, or ssl')
    if filename is not None and not filename.lower().endswith(('.log','.jsonl')): raise HTTPException(400,'Zeek upload must be a .log or .jsonl file')
    if len(data)>MAX_BYTES: raise HTTPException(413,'File exceeds 2 MB limit')
    try: lines=data.decode('utf-8-sig').splitlines()
    except UnicodeDecodeError: raise HTTPException(400,'File must be UTF-8')
    if not lines or len(lines)>MAX_ROWS: raise HTTPException(400,'File must contain 1 to 10,000 JSON lines')
    result=[]
    for number,line in enumerate(lines,1):
        try:
            raw=json.loads(line)
            if not isinstance(raw,dict): raise ValueError('record must be an object')
            timestamp=datetime.fromtimestamp(float(raw['ts']),timezone.utc)
            source=raw['id.orig_h']; destination=raw['id.resp_h']
            if not source or not destination: raise ValueError('source and destination IPs are required')
            origin_bytes=raw.get('orig_bytes')
            if origin_bytes in (None,'-'): origin_bytes=0
            kwargs=dict(timestamp=timestamp,source_ip=source,destination_ip=destination,
                source_port=raw.get('id.orig_p') if raw.get('id.orig_p') not in (None,'-') else None,
                destination_port=raw.get('id.resp_p') if raw.get('id.resp_p') not in (None,'-') else None,
                protocol=raw.get('proto') if raw.get('proto') not in (None,'-') else None,
                duration=raw.get('duration') if raw.get('duration') not in (None,'-') else None,
                connection_uid=raw.get('uid'),source_format=f'zeek_{log_type}',raw_event=raw,
                event_type=f'zeek_{log_type}',bytes_transferred=int(origin_bytes))
            if log_type=='dns': kwargs['query']=raw.get('query');kwargs['details']=f"DNS query: {raw.get('query','unknown')}"
            elif log_type=='http': kwargs['hostname']=raw.get('host');kwargs['details']=f"{raw.get('method','?')} {raw.get('uri','/')}"
            elif log_type=='ssl': kwargs['hostname']=raw.get('server_name');kwargs['details']=f"TLS server: {raw.get('server_name','unknown')}"
            else: kwargs['details']=f"Connection {raw.get('conn_state','unknown')}"
            result.append(EventInput.model_validate(kwargs))
        except KeyError as exc:
            raise HTTPException(422,{'line':number,'error':f'Missing required field: {exc.args[0]}'})
        except (ValueError,TypeError,OverflowError,ValidationError,RecursionError):
            raise HTTPException(422,{'line':number,'error':'Invalid Zeek field value'})
    return result
