# Sample provenance

- `zeek_conn.log`, `zeek_dns.log`, `zeek_http.log`, `zeek_ssl.log`, and `staged_auth.json` are **synthetic** demonstration fixtures written for NetSentry. Their field layout follows Zeek JSON logs; they were not emitted by a Zeek process.
- `zeek_official_conn.log` contains two actual Zeek-generated JSON `conn.log` examples reproduced from the [Zeek 7.2.2 documentation](https://docs.zeek.org/en/v7.2.2/logs/conn.html), with source attribution. They are parser smoke-test data, not the attack scenario.
- `security_events.csv`, `security_events.json`, and `evaluation_cases.json` are synthetic. The evaluation labels were designed with the rules and are not independent field measurements.
