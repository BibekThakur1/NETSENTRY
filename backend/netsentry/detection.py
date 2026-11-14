"""Explainable offline detections. ATT&CK references describe hypotheses, not proof."""
from collections import defaultdict
from datetime import timedelta
from ipaddress import ip_address
from .config import THRESHOLDS

ATTACK = {
 'brute_force':('T1110','Credential Access','Brute Force'),
 'port_scan':('T1046','Discovery','Network Service Discovery'),
 'high_traffic':('T1041','Exfiltration','Exfiltration Over C2 Channel'),
 'distributed_auth':('T1110','Credential Access','Brute Force'),
 'privilege_escalation':('T1098','Privilege Escalation','Account Manipulation'),
 'suspicious_ip':('T1071','Command and Control','Application Layer Protocol'),
 'dns_anomaly':('T1071.004','Command and Control','Application Layer Protocol: DNS'),
 'outbound_transfer':('T1041','Exfiltration','Exfiltration Over C2 Channel'),
 'auth_success_after_fail':('T1078','Initial Access','Valid Accounts'),
}
STEPS = {
 'brute_force':['Verify the account and source IP in identity logs.','Check successful logins after the failures.','Contact the account owner and consider a temporary block.'],
 'port_scan':['Review destination hosts and ports in firewall logs.','Identify whether the source is an approved scanner.','Scope other activity from this source.'],
 'high_traffic':['Compare volume with the host baseline.','Inspect destinations and protocols for data movement.','Confirm any scheduled backup or transfer.'],
 'distributed_auth':['Review targeted accounts and authentication outcomes.','Check for password spraying across other hosts.','Review MFA and lockout telemetry.'],
 'privilege_escalation':['Verify the admin change had an approved ticket.','Review actor and target account activity.','Revoke unexpected privileges and preserve audit logs.'],
 'suspicious_ip':['Validate indicator source and age.','Review all activity from the source.','Block or contain only after confirming impact.'],
 'dns_anomaly':['Inspect queried domain and subdomain length.','Compare with approved services and DNS baselines.','Review host processes if available.'],
 'outbound_transfer':['Verify destination ownership and transfer authorization.','Check for backup or data replication jobs.','Review related authentication and network events.'],
 'auth_success_after_fail':['Verify the successful login with the account owner.','Review MFA and login location.','Inspect later network activity from the source.'],
}
ATTACK_CONFIDENCE = {
 'brute_force':('medium','Failure burst is consistent with brute force, but intent is unknown.'),
 'port_scan':('medium','Distinct destination ports resemble service discovery.'),
 'high_traffic':('low','Volume alone does not establish exfiltration or a C2 channel.'),
 'distributed_auth':('medium','Many account names resemble password spraying.'),
 'privilege_escalation':('medium','Privilege change matches account manipulation, but may be approved.'),
 'suspicious_ip':('low','Indicator match alone does not identify an ATT&CK technique.'),
 'dns_anomaly':('low','Long distinct DNS names can be benign CDN or tracking activity.'),
 'outbound_transfer':('low','Outbound byte volume does not prove exfiltration or C2.'),
 'auth_success_after_fail':('low','A user may simply succeed after mistyping a password.'),
}
INDICATORS = {'203.0.113.66','198.51.100.77'}

def is_external(ip):
    try: return not ip_address(ip).is_private
    except (ValueError,TypeError): return False

def detect(events):
    events=sorted(events,key=lambda e:(e.timestamp,e.id))
    by_ip=defaultdict(list)
    for e in events: by_ip[e.source_ip].append(e)
    findings=[]
    def emit(rule,severity,title,group,evidence):
        anchor=group[-1]
        technique,tactic,name=ATTACK[rule]
        confidence,basis=ATTACK_CONFIDENCE[rule]
        fingerprint=f'{rule}:{anchor.source_ip}:{int(anchor.timestamp.timestamp()//60)}'
        findings.append(dict(timestamp=anchor.timestamp,source_ip=anchor.source_ip,rule=rule,severity=severity,title=title,evidence=evidence,
            attack={'technique_id':technique,'technique':name,'tactic':tactic,'interpretation':'Hypothesis; event metadata alone does not prove adversary intent.','mapping_confidence':confidence,'mapping_basis':basis},
            investigation_steps=STEPS[rule],event_ids=[e.id for e in group],fingerprint=fingerprint))
    for ip,group in by_ip.items():
        specs=[
            ('brute_force',lambda e:e.event_type=='login_failed',THRESHOLDS.auth_window_seconds,THRESHOLDS.brute_force,lambda es:len(es),'failed attempts','high'),
            ('port_scan',lambda e:e.event_type in ('connection','zeek_conn'),THRESHOLDS.port_window_seconds,THRESHOLDS.port_scan,lambda es:len({(getattr(e,'destination_ip',None),e.destination_port) for e in es if e.destination_port}),'distinct destination ports','high'),
            ('high_traffic',lambda e:e.event_type=='traffic',THRESHOLDS.traffic_window_seconds,THRESHOLDS.traffic_bytes,lambda es:sum(e.bytes_transferred for e in es),'bytes','medium'),
            ('distributed_auth',lambda e:e.event_type=='login_failed',THRESHOLDS.auth_window_seconds,THRESHOLDS.distributed_auth,lambda es:len({e.username for e in es if e.username}),'distinct accounts','high'),
            ('outbound_transfer',lambda e:e.event_type=='zeek_conn' and getattr(e,'destination_ip',None) and is_external(e.destination_ip),THRESHOLDS.traffic_window_seconds,THRESHOLDS.outbound_bytes,lambda es:sum(e.bytes_transferred for e in es),'outbound bytes','high'),
            ('dns_anomaly',lambda e:e.event_type=='zeek_dns' and getattr(e,'query',None) and len(e.query)>=THRESHOLDS.dns_query_length,THRESHOLDS.dns_window_seconds,THRESHOLDS.dns_unique_queries,lambda es:len({e.query for e in es}),'long unique DNS queries','medium'),
        ]
        for rule,predicate,window,threshold,measure,unit,severity in specs:
            typed=[e for e in group if predicate(e)]
            left=0
            for right,end in enumerate(typed):
                while typed[left].timestamp<end.timestamp-timedelta(seconds=window):left+=1
                current=typed[left:right+1]
                value=measure(current)
                bucket=int(end.timestamp.timestamp()//60)
                if value>=threshold:
                    emit(rule,severity,rule.replace('_',' ').title(),current,{'observed':value,'threshold':threshold,'window_seconds':window,'unit':unit,'source_ip':ip})
        failed=[e for e in group if e.event_type=='login_failed']
        for success in (e for e in group if e.event_type=='login_success'):
            recent=[e for e in failed if 0<=(success.timestamp-e.timestamp).total_seconds()<=THRESHOLDS.auth_window_seconds and e.username==success.username]
            if len(recent)>=THRESHOLDS.auth_pre_success:
                emit('auth_success_after_fail','high','Login success after repeated failures',recent+[success],{'failed_attempts':len(recent),'username':success.username,'window_seconds':THRESHOLDS.auth_window_seconds})
        for e in group:
            if e.event_type=='privilege_change': emit('privilege_escalation','critical','Privilege change requires review',[e],{'actor':e.username,'details':e.details or 'Privilege change event','event_id':e.id})
        if ip in INDICATORS: emit('suspicious_ip','high','Source matches local indicator',group,{'indicator':ip,'source':'bundled demonstration list','events_seen':len(group)})
    return list({f['fingerprint']:f for f in findings}.values())
