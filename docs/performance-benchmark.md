# Local synthetic performance benchmark

Run `cd backend && ../.venv/bin/python -m scripts.benchmark --sizes 1000 10000 100000` to regenerate `docs/performance-benchmark.json`. Each size uses a fresh temporary SQLite database and sends multipart JSON uploads through the actual FastAPI TestClient endpoint. Each file has at most 10,000 rows. The test machine reported macOS 26.6.2, ARM64, Python 3.13.0, and 8 logical CPUs.

| Events | Files | End-to-end wall time | Throughput | Detection time | Correlation time | Peak RSS |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 1 | 0.188 s | 5,318.7 events/s | 3.23 ms | 0.32 ms | 87.9 MB |
| 10,000 | 1 | 1.593 s | 6,275.5 events/s | 32.04 ms | 3.18 ms | 153.5 MB |
| 100,000 | 10 | 16.706 s | 5,985.7 events/s | 340.18 ms total | 34.13 ms total | 152.0 MB |

The event mix is **normal synthetic login_success events only**, distributed across sources. No alerts or incidents are expected. Detection and correlation times are sums across uploads; wall time includes validation, database writes, queries, and response handling. Peak RSS is measured for each isolated process. This is an in-process API benchmark, not a networked deployment or production capacity test. Dense attack windows, one hot source, real Zeek raw payloads, and PostgreSQL may behave differently. The 100,000-event run demonstrates completion without a crash under these conditions; it does not establish a sustained ingest rate or safe production scale.

A prior run exposed an N+1 database reload in correlation. Reloading affected-source rows in one query reduced the 100,000-event wall time from 25.136 s to 16.706 s under the same synthetic scenario. This comparison is directional because these are single local runs, not controlled repetitions.
