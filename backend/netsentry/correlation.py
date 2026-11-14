"""Deterministic multi-stage correlation over offline event history."""
from collections import defaultdict
from datetime import timedelta, timezone
from ipaddress import ip_address
from .config import THRESHOLDS

def utc_iso(value):
    if value.tzinfo is None:value=value.replace(tzinfo=timezone.utc)
    return value.isoformat()

def internal(ip):
    if not ip:return False
    try:return ip_address(ip).is_private
    except ValueError:return False

def correlate(events,alerts):
    by_ip=defaultdict(list); alerts_by_ip=defaultdict(list)
    for event in events:by_ip[event.source_ip].append(event)
    for alert in alerts:alerts_by_ip[alert.source_ip].append(alert)
    incidents=[]
    for ip,all_events in by_ip.items():
        if not any(a.rule=='port_scan' for a in alerts_by_ip[ip]):continue
        all_events.sort(key=lambda e:e.timestamp)
        for start_index,start in enumerate(all_events):
            window_end=start.timestamp+timedelta(seconds=THRESHOLDS.correlation_window_seconds)
            window=[e for e in all_events[start_index:] if e.timestamp<=window_end]
            if len(window)<3:continue
            stages=[]
            scan_alert=next((a for a in alerts_by_ip[ip] if a.rule=='port_scan' and start.timestamp<=a.timestamp<=window_end),None)
            if not scan_alert:continue
            scan_events=[e for e in window if e.id in scan_alert.event_ids]
            if not scan_events:continue
            stages.append({'name':'Reconnaissance','timestamp':utc_iso(scan_alert.timestamp),'event_ids':[e.id for e in scan_events],'reason':'Port-scan alert from this source IP.'})
            after_scan=max(e.timestamp for e in scan_events)
            failed=[e for e in window if e.event_type=='login_failed' and e.timestamp>=after_scan]
            successes=[e for e in window if e.event_type=='login_success' and e.timestamp>=after_scan]
            success=next((s for s in successes if s.username and len([f for f in failed if f.username==s.username and f.timestamp<=s.timestamp])>=THRESHOLDS.auth_pre_success),None)
            if not success:continue
            auth=[f for f in failed if f.username==success.username and f.timestamp<=success.timestamp]
            stages.append({'name':'Initial access','timestamp':utc_iso(success.timestamp),'event_ids':[e.id for e in auth+[success]],'reason':f'{len(auth)} failed logins followed by success for the same user.'})
            lateral=next((e for e in window if e.timestamp>success.timestamp and e.event_type in ('connection','zeek_conn') and internal(e.destination_ip) and e.destination_port in (22,3389,445,5985)),None)
            if lateral:
                stages.append({'name':'Possible lateral movement','timestamp':utc_iso(lateral.timestamp),'event_ids':[lateral.id],'reason':'Remote-service connection to an internal destination after login; metadata cannot prove access.'})
            outbound=next((e for e in window if e.timestamp>success.timestamp and e.event_type=='zeek_conn' and e.bytes_transferred>=THRESHOLDS.outbound_bytes and e.destination_ip and not internal(e.destination_ip)),None)
            if outbound:
                stages.append({'name':'Possible outbound transfer','timestamp':utc_iso(outbound.timestamp),'event_ids':[outbound.id],'reason':f'{outbound.bytes_transferred} origin bytes sent to an external destination; content is unknown.'})
            if len(stages)<3:continue
            used_ids=sorted({eid for stage in stages for eid in stage['event_ids']})
            related_alerts=[a.id for a in alerts_by_ip[ip] if start.timestamp<=a.timestamp<=window_end and set(a.event_ids)&set(used_ids)]
            confidence=round(min(0.95,0.55+0.1*(len(stages)-2)+0.05*bool(related_alerts)),2)
            fingerprint=f'{ip}:{scan_alert.id}:{success.id}'
            incidents.append(dict(fingerprint=fingerprint,timestamp=stages and start.timestamp,title='Correlated multi-stage activity',source_ip=ip,
                severity='critical' if outbound else 'high',confidence=confidence,
                severity_reason='Critical because correlated authentication and reconnaissance are followed by a large external transfer.' if outbound else 'High because reconnaissance and suspicious authentication precede internal remote-service activity.',stages=stages,event_ids=used_ids,alert_ids=sorted(set(related_alerts))))
            break
    return incidents
