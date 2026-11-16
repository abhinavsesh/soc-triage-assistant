"""Time the ingest endpoint on a synthetic batch (temporary database, real detection code).
This is a timing check, not an accuracy test: it reports whatever the detectors find."""
import os
import tempfile
import time
from pathlib import Path

tmp = Path(tempfile.mkdtemp())
os.environ["DATABASE_URL"] = f"sqlite:///{tmp / 'bench.db'}"
os.environ["ANALYST_KEYS"] = "bench-key:bench_analyst"

from fastapi.testclient import TestClient  # noqa: E402

from soc_triage.api.main import app  # noqa: E402


def main():
    events = []
    for i in range(4900):
        events.append({
            "timestamp": f"2026-11-10T{9 + (i // 600) % 8:02d}:{i % 60:02d}:{(i * 7) % 60:02d}",
            "user": f"user{i % 300}", "src_ip": f"10.0.{i % 5}.{i % 250 + 1}",
            "result": "failure" if i % 25 == 0 else "success"})
    for s in range(6):
        events.append({"timestamp": f"2026-11-10T13:02:{s * 10:02d}", "user": "victim",
                       "src_ip": "203.0.113.9", "result": "failure"})
    events.append({"timestamp": "2026-11-10T13:03:10", "user": "victim",
                   "src_ip": "203.0.113.9", "result": "success"})
    with TestClient(app) as c:
        h = {"X-API-Key": "bench-key"}
        t0 = time.perf_counter()
        r = c.post("/ingest/auth", json={"events": events}, headers=h)
        t1 = time.perf_counter()
        a = c.get("/alerts", headers=h)
        t2 = time.perf_counter()
    print(r.status_code, r.json())
    print(f"ingest of {len(events)} events: {t1 - t0:.2f} s ({len(events) / (t1 - t0):.0f} events/s)")
    print(f"list alerts: {(t2 - t1) * 1000:.0f} ms, {len(a.json())} alerts")


if __name__ == "__main__":
    main()
