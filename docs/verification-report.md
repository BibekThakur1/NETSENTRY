# NetSentry verification report

## Scope and method

The repository was inspected for connected frontend actions, API routes, parsers, detections, correlation, storage, sample provenance, and deployment. Automated tests use isolated temporary databases and the actual FastAPI TestClient routes. Synthetic demo data flows through the same parsers, event storage, detection, and correlation functions as manual imports. The main dataset remains untouched by demo resets.

## Feature verification matrix

| Workflow | Evidence | Result |
| --- | --- | --- |
| CSV authentication and generic JSON import | Full API integration; sample CSV and staged auth | Pass |
| Zeek conn, dns, http, ssl import | Full API integration and parser tests | Pass |
| Raw event and provenance retention | Zeek TLS raw record assertion; event search API | Pass |
| All nine detection rules | Labelled scenario evaluator and full API integration | Pass on synthetic fixtures |
| ATT&CK metadata | Every alert inspected in API integration | Pass; hypothesis only |
| Multi-stage correlation | Four-stage incident API and demo isolation tests | Pass |
| Event search and filters | Source, event type, text search integration | Pass |
| Asset inventory and activity | Assets and asset-events API integration | Pass |
| Assignment, status, notes | Incident PATCH integration | Pass |
| Simulated response and audit history | Action POST and audit count integration | Pass |
| JSON incident export | Export content integration | Pass |
| One-click isolated demo | Run twice; main DB unchanged; one incident each time | Pass |
| Frontend wiring | TypeScript/Vite build; browser-clicked Run Scenario, incident, alerts, assets, evaluation | Pass |
| Docker Compose | Built and ran PostgreSQL, FastAPI and Nginx; health and synthetic demo checked through port 8080 | Pass |

No placeholder buttons were found in the inspected React source. The import picker posts to the relevant API endpoint; Incidents and Assets use API reads; investigation controls use PATCH/POST; export uses the report endpoint. Screenshots in `docs/screenshots/` were captured from the running Docker app after the scenario completed. A narrated demo video remains to be recorded.

## Browser and Docker observations

The Run Scenario button completed in the actual Nginx-served UI and displayed 41 synthetic events, four alerts, one incident and the measured processing time. The incident view showed four stages, supporting timeline, assignment fields, simulated response controls and audit history. The asset table opened the event explorer for the selected IP; the alert drawer showed threshold evidence and ATT&CK mapping confidence; the evaluation tab showed scenario counts and per-rule results. The app was rebuilt and retested after fixing a misleading asset hostname and adding a visible incident count. The main PostgreSQL dataset stayed empty while the demo SQLite dataset held the scenario.

## Detection evaluation

The 13-case labelled corpus contains nine positive rule-scenario pairs and four all-negative scenarios: normal authentication, repeated connections to one port, short DNS queries, and a large internal backup. Nine rules across 13 scenarios produce 117 rule-scenario decisions: TP 9, FP 0, FN 0, TN 108. Precision, recall and F1 are 1.000 on these **designed synthetic fixtures only**. The labels were not independent of the rule design. See `docs/detection-evaluation.json` and `docs/evaluation-report.md`.

Boundary tests cover below/exact thresholds, reverse event order, missing timestamps, invalid IPs, oversized files, unsupported Zeek filenames, incomplete Zeek records, and duplicate imports. A parser error that echoed the invalid value was found and fixed. Alerts now update evidence when later events strengthen the same rule/minute finding while preserving investigation notes.

## Performance and security

See `docs/performance-benchmark.md` and `docs/security-review.md`. The 100,000-event synthetic normal-data run completed in 16.706 seconds across 10 API uploads on the local machine. This does not cover dense attack traffic or production network conditions. Dependency audits found no known advisories after the Vite update. The app remains local-only with no login, so it is not suitable for private real logs or public exposure.

## Exact reproduction

1. Create a Python virtual environment and install `backend/requirements.txt`.
2. Run `cd backend && ../.venv/bin/pytest -q`.
3. Run `cd backend && ../.venv/bin/python -m scripts.evaluate`.
4. Run `cd backend && ../.venv/bin/python -m scripts.benchmark --sizes 1000 10000 100000` (the last size takes longer).
5. Run `cd frontend && npm ci && npm run build`.
6. Start backend and frontend as in README, open the app, and click **Run Scenario**. It resets only the separate demo database and creates one four-stage incident.
7. Inspect the alert evidence, incident timeline, notes, audit history, and export. Switch back to the main dataset with **Return to main**.
8. If Docker Desktop is available, run `docker compose up --build -d` and open `http://localhost:8080`; use `docker compose down` to stop it without deleting the volume.

## Remaining portfolio work

A narrated 2-3 minute demo video must be recorded by the project owner. Versioned migrations, authentication, stronger real-data evaluation, and dense-window load tests remain engineering follow-ups. The repository includes a GitHub Actions workflow for backend tests, synthetic evaluation, frontend build, production dependency audit, and Compose image build; its remote results should be checked after publishing.
