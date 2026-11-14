"""Deterministic labelled, synthetic detection scenarios."""
import json
from datetime import datetime,timedelta,timezone
from pathlib import Path
start=datetime(2026,11,14,8,0,tzinfo=timezone.utc)
cases=[]
def add(name,expected,rows):cases.append({'name':name,'expected_rules':expected,'events':rows})
def e(i,typ,ip='192.0.2.10',**kwargs):return {'timestamp':(start+timedelta(seconds=i)).isoformat(),'source_ip':ip,'event_type':typ,**kwargs}
add('normal_auth',[],[e(i*10,'login_success',username='employee') for i in range(8)])
add('brute_force',['brute_force'],[e(i*4,'login_failed',username='admin') for i in range(10)])
add('port_scan',['port_scan'],[e(i*2,'connection',destination_ip='10.0.0.10',destination_port=1000+i) for i in range(20)])
add('traffic_spike',['high_traffic'],[e(i*5,'traffic',bytes_transferred=250000) for i in range(4)])
add('password_spray',['distributed_auth'],[e(i*5,'login_failed',username=f'user{i}') for i in range(8)])
add('privilege_change',['privilege_escalation'],[e(1,'privilege_change',username='admin',details='Added member to admins')])
add('local_indicator',['suspicious_ip'],[e(1,'connection',ip='203.0.113.66',destination_ip='10.0.0.10',destination_port=443)])
add('success_after_fail',['auth_success_after_fail'],[e(i*5,'login_failed',username='analyst') for i in range(5)]+[e(30,'login_success',username='analyst')])
add('outbound_volume',['outbound_transfer'],[e(1,'zeek_conn',destination_ip='8.8.8.8',destination_port=443,bytes_transferred=6000000)])
add('dns_long_queries',['dns_anomaly'],[e(i*20,'zeek_dns',query='a'*48+str(i)+'.demo.example',destination_ip='10.0.0.53') for i in range(5)])
add('single_port_connections',[],[e(i,'connection',destination_ip='10.0.0.10',destination_port=443) for i in range(25)])
add('short_dns_queries',[],[e(i*20,'zeek_dns',query=f'normal{i}.example',destination_ip='10.0.0.53') for i in range(5)])
add('internal_backup',[],[e(1,'zeek_conn',destination_ip='10.0.0.20',destination_port=445,bytes_transferred=6000000)])
Path('samples/evaluation_cases.json').write_text(json.dumps(cases,indent=2)+'\n')
print(len(cases),'labelled scenarios')
