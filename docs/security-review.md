# Security review

## Controls verified

- Generic uploads allow only CSV/JSON; Zeek uploads require an explicit log type and `.log` or `.jsonl` filename. Both have UTF-8, 2 MB and 10,000-row limits, atomic validation, timezone-aware timestamps, valid IP/port checks, and bounded text fields. Malformed rows return row/field codes without echoing the invalid value.
- SQLAlchemy query builders use bound parameters. Event search is capped at 100 characters and result lists at 500 rows.
- Synthetic demo reset operates only on a separate SQLite database. Startup rejects identical main and demo database URLs. Normal data is unchanged across demo runs in the integration test.
- Docker Compose binds public ports to `127.0.0.1`; the local Vite script also binds loopback. No active scanning or real response action exists.
- `npm audit --omit=dev` reported 0 advisories after upgrading Vite and its React plugin. `pip-audit -r backend/requirements.txt` reported no known vulnerabilities across 31 resolved Python dependencies on the review date. Registries and advisories change; rerun these checks before publishing.

## Open risks and limits

- There is **no authentication or authorization**. Anyone able to reach the local API can read events and incident notes, update investigations, or trigger demo reset. Do not expose the app beyond a trusted local machine or import sensitive real logs.
- CORS is not an authentication or CSRF control. A hardened shared deployment needs login, roles, CSRF protection, session security, and audit actor identity from authenticated users.
- PostgreSQL credentials in `compose.yaml` are fixed local-demo credentials. They must be replaced and managed as secrets before any shared deployment.
- Raw events can contain private network metadata and usernames. The app has no retention or redaction policy. The included data is synthetic except for two attributed Zeek documentation examples.
- Incident audit entries are append-only through the API but not cryptographically immutable; a database administrator can alter them.
- Database schema creation and additive SQLite column updates are not versioned migrations. PostgreSQL schema evolution needs a migration tool before long-lived use.
- External threat intelligence is not used. ATT&CK mappings and incident confidence are hypotheses, not verified attacker attribution or calibrated probability.
