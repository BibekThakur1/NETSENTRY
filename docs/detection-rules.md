# Detection rules and ATT&CK hypotheses

ATT&CK mappings provide a vocabulary for investigation. They do not assert that a technique occurred. See [MITRE ATT&CK](https://attack.mitre.org/) and the [Zeek log reference](https://docs.zeek.org/en/current/reference/zeekscript/log-files.html).

| Rule | Trigger | Severity | ATT&CK hypothesis | Common benign explanation |
| --- | --- | --- | --- | --- |
| Brute force | 10 failed logins from one source in 60 seconds | High | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Mistyped service password; shared NAT |
| Port scan | 20 distinct destination IP/port pairs in 60 seconds | High | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Approved vulnerability scanner |
| High traffic | 1,000,000 generic traffic bytes in 60 seconds | Medium | [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Backup or bulk transfer; mapping is weak without destination or C2 evidence |
| Distributed auth | 8 distinct failed usernames from one source in 60 seconds | High | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Federation proxy or test harness |
| Privilege change | Any privilege_change event | Critical | [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) | Approved admin ticket |
| Suspicious IP | Source matches bundled demonstration list | High | [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) | Demo indicator only; no real threat feed |
| DNS anomaly | 5 distinct queries of at least 45 characters in 5 minutes | Medium | [T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004/) | CDN or tracking domains |
| Outbound transfer | 5,000,000 Zeek origin bytes to external IP in 60 seconds | High | [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Approved data transfer; volume alone cannot prove exfiltration or C2 |
| Login success after failures | 5 failures then success for same user/source within 60 seconds | High | [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) | User finally entering correct password |

Thresholds are in `backend/netsentry/config.py`. Alert evidence records observed values, thresholds, windows and supporting event IDs when applicable. Each ATT&CK mapping also includes a low or medium mapping-confidence label and a basis explaining the limits of the inference. Analysts should review destination ownership, approved testing, backup schedules, identity logs, MFA and host activity before deciding whether an alert is malicious.

## Correlated incident

Within 30 minutes and one source IP, NetSentry requires a port scan plus failed logins followed by a success for the same user and at least one subsequent remote-service or large outbound connection. The incident records stage-level evidence and a heuristic confidence score. Shared NAT or reused source IPs can join unrelated behavior. The score is not calibrated to real attack likelihood.
