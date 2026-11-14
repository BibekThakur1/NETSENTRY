# NetSentry 2.0 implementation plan

Acceptance criteria:

1. Import Zeek JSON lines from conn, dns, http, and ssl logs; reject malformed rows atomically; retain raw records, provenance, and normalized fields.
2. Keep prior CSV/JSON imports and six rules working. Add DNS anomaly, outbound transfer, and suspicious login success rules with explainable evidence and ATT&CK references.
3. Correlate recon, authentication, lateral movement, and outbound transfer into one incident with event IDs, alert IDs, confidence, and a timeline; avoid duplicate incidents on repeated imports.
4. Provide asset inventory, event search, incident assignment, status, notes, simulated response actions, audit history, and export.
5. Compute precision, recall, F1 and false-positive rate from a labelled synthetic corpus; report per-rule results and run automated tests.
6. Provide local Docker Compose, setup docs, architecture, rule descriptions, limits, and a working demo dataset.

Audit findings in the initial prototype: only generic CSV/JSON events, no network-native schema or raw provenance, O(n²) window scans, minute-based alert deduplication, no incident entity, no search or audit log, no measured detection quality, no deployment bundle, and no API authentication. The local-only security boundary remains explicit.

## Completion evidence

- Zeek parsing and malformed-row checks: `backend/tests/test_zeek_incident.py`.
- Four-stage incident and analyst workflow: staged integration test in the same file.
- Labelled evaluation: `backend/tests/test_evaluation.py` and `docs/detection-evaluation.json`.
- Legacy feature regression: original tests retained.
- Local Docker configuration: `docker compose config --quiet`.
