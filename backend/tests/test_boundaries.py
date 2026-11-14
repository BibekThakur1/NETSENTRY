from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import json
import pytest
from fastapi import HTTPException
from netsentry.detection import detect
from netsentry.ingest import parse_upload,MAX_BYTES
from netsentry.zeek import parse_zeek

T=datetime(2026,1,1,tzinfo=timezone.utc)
def event(i,kind,sec,**kw):
    return SimpleNamespace(id=i,timestamp=T+timedelta(seconds=sec),source_ip='192.0.2.40',event_type=kind,
      destination_ip=kw.get('destination_ip'),destination_port=kw.get('destination_port'),username=kw.get('username'),
      bytes_transferred=kw.get('bytes_transferred',0),query=kw.get('query'),details=None)
def rules(events):return {a['rule'] for a in detect(events)}

def test_threshold_edges_and_out_of_order():
    failures=[event(i,'login_failed',i*6,username='admin') for i in range(10)]
    assert 'brute_force' not in rules(failures[:9])
    assert 'brute_force' in rules(list(reversed(failures)))
    assert 'brute_force' in rules([event(i,'login_failed',i*6,username='admin') for i in range(11)])
    ports=[event(i,'zeek_conn',i*3,destination_ip='10.0.0.10',destination_port=1000+i) for i in range(20)]
    assert 'port_scan' not in rules(ports[:19])
    assert 'port_scan' in rules(list(reversed(ports)))
    dns=[event(i,'zeek_dns',i*30,query='x'*46+str(i)) for i in range(5)]
    assert 'dns_anomaly' not in rules(dns[:4])
    assert 'dns_anomaly' in rules(dns)
    assert 'outbound_transfer' not in rules([event(1,'zeek_conn',1,destination_ip='8.8.8.8',bytes_transferred=4_999_999)])
    assert 'outbound_transfer' in rules([event(1,'zeek_conn',1,destination_ip='8.8.8.8',bytes_transferred=5_000_000)])

def test_bad_fields_are_rejected_without_raw_input_echo():
    base={'timestamp':'2026-01-01T00:00:00Z','source_ip':'192.0.2.1','event_type':'login_failed'}
    for bad in ({**base,'source_ip':'not-an-ip'},{k:v for k,v in base.items() if k!='timestamp'},
                {**base,'destination_port':70000}):
        with pytest.raises(HTTPException) as error:parse_upload('events.json',json.dumps([bad]).encode())
        assert error.value.status_code==422
        assert 'not-an-ip' not in str(error.value.detail)
    with pytest.raises(HTTPException) as error:parse_upload('events.json',b'x'*(MAX_BYTES+1))
    assert error.value.status_code==413
    with pytest.raises(HTTPException) as error:parse_upload('events.json',b'["not an object"]')
    assert error.value.status_code==422
    with pytest.raises(HTTPException) as error:parse_zeek('conn',b'{"ts":1}',filename='events.txt')
    assert error.value.status_code==400
    with pytest.raises(HTTPException) as error:parse_zeek('conn',b'{"ts":1}\n',filename='conn.log')
    assert error.value.status_code==422 and error.value.detail['line']==1
