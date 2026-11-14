from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from netsentry.detection import detect
from netsentry.ingest import parse_upload
from fastapi import HTTPException
import pytest

T=datetime(2026,1,1,tzinfo=timezone.utc)
def ev(i,typ,ip='192.0.2.1',sec=0,port=None,user=None,bytes_=0):
 return SimpleNamespace(id=i,timestamp=T+timedelta(seconds=sec),source_ip=ip,event_type=typ,destination_port=port,username=user,bytes_transferred=bytes_,details='approved change')

def rules(es): return {a['rule'] for a in detect(es)}

def test_brute_force_and_boundary():
 es=[ev(i,'login_failed',sec=i*5,user='admin') for i in range(10)]
 assert 'brute_force' in rules(es)
 assert 'brute_force' not in rules(es[:9])
 assert 'brute_force' not in rules([ev(i,'login_failed',sec=i*70) for i in range(10)])

def test_port_scan_distinct_ports_only():
 assert 'port_scan' in rules([ev(i,'connection',sec=i,port=1000+i) for i in range(20)])
 assert 'port_scan' not in rules([ev(i,'connection',sec=i,port=443) for i in range(30)])

def test_traffic_threshold_and_normal():
 assert 'high_traffic' in rules([ev(i,'traffic',sec=i,bytes_=250000) for i in range(4)])
 assert 'high_traffic' not in rules([ev(i,'traffic',sec=i,bytes_=1000) for i in range(4)])

def test_other_rules():
 assert 'distributed_auth' in rules([ev(i,'login_failed',sec=i,user=f'user{i}') for i in range(8)])
 assert 'distributed_auth' not in rules([ev(i,'login_failed',sec=i,user='same') for i in range(8)])
 assert 'privilege_escalation' in rules([ev(1,'privilege_change')])
 assert 'suspicious_ip' in rules([ev(1,'connection',ip='203.0.113.66')])

def test_upload_validation():
 with pytest.raises(HTTPException): parse_upload('x.txt',b'hello')
 with pytest.raises(HTTPException): parse_upload('x.json',b'not json')
 with pytest.raises(HTTPException): parse_upload('x.json',b'[{}]')
 with pytest.raises(HTTPException): parse_upload('x.json',b'[]')
