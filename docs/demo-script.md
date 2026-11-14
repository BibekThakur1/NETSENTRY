# Three-minute demo

1. Show the architecture diagram in README and explain local-first offline ingest.
2. Start the app with `docker compose up --build` or the two local dev commands.
3. Click **Run Scenario**. Explain that the app resets only its isolated demo database, then imports the five bundled synthetic files through the normal pipeline. The UI should report 41 events, four alerts, and one incident.
4. Open the correlated incident. Explain why the four stages are linked by source IP, user and 30-minute window. Point out that lateral movement and exfiltration are **possible**, not proven.
5. Open an alert and show the evidence count, threshold, event timeline and ATT&CK hypothesis.
6. Assign the incident, add a note, record a simulated response, show the audit trail, and export the JSON report.
7. Open Assets, Event explorer and Evaluation. State that the evaluation scores come from small synthetic fixtures.
8. Run backend tests and frontend build; explain the no-auth local boundary and future improvements.
