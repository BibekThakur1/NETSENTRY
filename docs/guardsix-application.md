# NetSentry for a Guardsix application

NetSentry is an independent portfolio prototype. It is not a Guardsix product, integration, or reproduction. Use it to discuss engineering choices and analyst workflow in an interview, with the limitations below stated plainly.

## Why this project is relevant

Guardsix describes a connected SIEM, NDR, and SOAR investigation workflow. Its NDR material highlights network telemetry, assets, raw metadata, and a navigable attack timeline; its SOAR documentation explains how incidents become cases with investigation and response context. NetSentry explores a small, offline slice of that problem: normalize Zeek and identity records, attach evidence to detections, correlate a four-stage timeline, and record an analyst's decisions. It does not provide Guardsix's live sensors, machine learning, integrations, automation, scale, or deployment assurances.

| Guardsix-facing discussion | Evidence in NetSentry | Honest boundary |
| --- | --- | --- |
| NDR and SIEM data in one investigation | Zeek conn/dns/http/ssl plus authentication imports; normalized schema and original record provenance | Offline imports; no packet capture or live connectors |
| Explainable detection | Nine documented rules with thresholds, evidence, investigation steps, and ATT&CK hypotheses | Handwritten rules; synthetic labels do not measure field accuracy |
| Attack-chain investigation | Four-stage incident with timeline, related alert/event IDs, severity reason, and heuristic confidence | Source-IP correlation can misattribute shared NAT traffic |
| SOC and case workflow | Assignment, status, notes, audit history, JSON export, and simulated response actions | No real blocking, automation, user identity, or RBAC |
| Operator trust | Isolated one-click demo; deterministic fixtures; boundary tests; reproducible benchmark and security review | Local-only, no confidential customer telemetry |

## Application-ready project description

**NetSentry 2.0 — Network Threat Detection and Investigation Prototype**

Python, FastAPI, SQLAlchemy, PostgreSQL/SQLite, Zeek JSON logs, React, TypeScript, Docker Compose

> Built an offline network security investigation prototype that normalizes Zeek and authentication logs, preserves raw evidence, runs nine explainable detection rules, and correlates alerts into a four-stage incident. Added analyst notes, status, audit history, simulated response actions, and JSON export. Verified the workflow with 16 automated backend tests, a production frontend build, an isolated one-click demo, and reproducible synthetic evaluation and performance reports.

For an interview, show the [dashboard](screenshots/dashboard.jpg), [incident investigation](screenshots/incident-investigation.jpg), [evaluation](screenshots/evaluation.jpg), and [verification report](verification-report.md). Run `docker compose up --build`, open `http://localhost:8080`, and click **Run Scenario**. Explain what each piece of evidence supports and what it cannot establish.

## Questions to prepare for

- **Why normalize and preserve raw events?** Normalization allows cross-source rules; raw records let an analyst verify the parser's interpretation.
- **How do you avoid misleading detection claims?** The 13 labelled scenarios test intended rule behavior. The 9 TP / 0 FP / 0 FN / 108 TN result is only for rule-scenario pairs in designed synthetic fixtures.
- **What is the next production step?** Add authenticated analyst identity and RBAC, versioned migrations, retention/redaction, independent real-data evaluation, and incremental processing before considering a shared deployment.
- **What would change for an MSSP?** Strong tenant isolation, per-tenant access control and retention, workload limits, operational telemetry, and independently measured false-positive rates would be required. None is implemented here.

## Source context

- [Guardsix careers](https://guardsix.com/join-us) describes its support for MSSPs, SOC teams, and critical infrastructure defenders.
- [Guardsix NDR](https://guardsix.com/product/ndr) describes network telemetry and an investigation timeline.
- [Guardsix SOAR documentation](https://docs.guardsix.com/soar) describes the relationship between events, alerts, incidents, cases, and response workflows.
