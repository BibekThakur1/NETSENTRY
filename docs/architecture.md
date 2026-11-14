# NetSentry 2.0 architecture and engineering notes

## Pipeline

Offline CSV/JSON and Zeek JSON lines are validated before any database write. Pydantic enforces UTC-aware timestamps, IP addresses, ports, nonnegative bytes, and bounded text. The common event schema includes source and destination IP/port, protocol, duration, Zeek UID, hostname or DNS query, event type, user, byte count, provenance, and preserved raw JSON. SQLAlchemy persists events, alerts, incidents, import digests, and audit entries. The import transaction either writes all rows and detections or writes none.

Zeek `conn.log`, `dns.log`, `http.log`, and `ssl.log` JSON formats are supported. Source/destination and `ts` are required. `orig_bytes` is treated as outbound bytes from the originator, not total flow bytes. Missing optional Zeek fields remain null. For HTTP and TLS, host/server name is retained. This is **offline Zeek log ingestion**, not live packet monitoring.

## Detection and correlation

Rule thresholds live in `backend/netsentry/config.py`. The engine evaluates stored events and produces alerts with supporting event IDs, evidence, investigation steps, and an ATT&CK hypothesis. The correlation engine seeks a port-scan alert, failed logins followed by a success for the same user, then an internal remote-service connection and/or a large outbound Zeek connection from the same source IP within 30 minutes. It records stage reasons, event IDs, related alert IDs, severity and a deterministic confidence score. The confidence score is a heuristic, not a calibrated probability.

The demo incident has four stages. Correlation does not assume a remote-service connection proves lateral movement or a large outbound transfer proves exfiltration; both are labelled **possible**. For actual attribution, host telemetry and account-to-session linkage would be needed.

## Search, inventory and investigation

Event API filters include source, destination, event type, username and bounded text search. Passive inventory derives first/last seen, connections, alert count and an illustrative risk score from imported events. Risk score is not an empirical threat score. Incidents support Open -> Investigating -> Contained -> Resolved, assignment, notes, simulated response actions, audit entries and JSON export. Actions never affect live systems.

## Storage and deployment

Local Python uses SQLite. Docker Compose uses PostgreSQL and binds web/API ports to loopback. A separate SQLite database holds the one-click synthetic demo and can be reset without changing the main database. SQLAlchemy `create_all` creates the schema; an additive SQLite migration covers existing columns. A full production system would use versioned migrations, durable workers, queueing, partitioning, authentication, retention, backups, and access logs. Each import re-evaluates stored history only for affected source IPs and should stay bounded to small offline datasets. Incident deduplication uses source and anchor event IDs; alert deduplication uses source, rule, and minute.

## Security boundary

The app is an analyst demo for a trusted local environment. It has no authentication or RBAC. Do not expose its ports publicly or import sensitive logs. Uploads accept only CSV, JSON, or the explicit Zeek JSON-lines endpoint, with a 2 MB and 10,000-row limit. File validation is atomic. The attack scenario records are synthetic; two attributed Zeek-generated connection records provide a parser smoke test. Response actions are audit-only simulations.

## Future work

Incremental window state, stronger identity/host correlation, source-specific parsing coverage, trusted analyst login, immutable audit storage, measured thresholds on diverse labelled data, and real asset enrichment are the main next steps. Kafka, Kubernetes and OpenSearch are unnecessary at this prototype scale.
