# Production readiness: what exists, what does not

Review date: 2026-11-16. This is a local prototype. The aim of this file is to say plainly which production practices are in place, which are not, and what I would do about each.

## What exists
- **Modular code with separated concerns:** ingestion, features, detection, scoring, MITRE mapping, LLM, agent tools, API, dashboard. Each part can be tested and replaced on its own.
- **Configuration through environment variables.** Secrets live in an ignored .env file, with a committed .env.example containing placeholders only.
- **Logging** with a request id and timing on every request. Request bodies, query strings and usernames are never logged, which also prevents log forging.
- **An audit table** recording who changed what and when. Each audit row is written in the same transaction as the change it describes.
- **113 automated tests**, including an end-to-end test of the sample file against the alerts derived by hand, hostile-input tests, authorisation tests and four-eyes approval tests. GitHub Actions runs them on every push, and the latest run was green (about one minute).
- **Input validation at the API boundary** (unknown fields, wrong types and oversized batches are rejected), constraints in the database, and graceful errors: 503 when the model server is down, and a generic 500 with a request id for anything unexpected, with no stack trace sent to the client.
- **Reliability checks performed by hand:** with the model server stopped, the dashboard showed a 503 message and the rest of the alert page kept working. With the API stopped, the dashboard showed a clear not-reachable message. A wrong key gave a 401 and no sign-in. After restarting the server, alerts, statuses and approvals were still present.
- **Security checks:** secrets scan of the repository and its history, dependency audit, static analysis with bandit, and live checks of authentication and input validation. Results are in docs/security_review.md.
- **Timing:** ingesting 4,907 events took 0.48 s (about 10,000 events per second), and listing alerts took 4 ms. This was one in-process run against a temporary database, so it excludes network and disk contention. The model call takes about 20 to 40 seconds and is the real bottleneck.

## What does not exist, and what I would do
| Gap | Production approach |
|---|---|
| No Docker image | A Dockerfile with a pinned base image, a non-root user, a health check and dependencies installed from requirements.txt |
| SQLite | Postgres with migrations (for example Alembic) and backups. SQLite allows one writer at a time |
| Static API keys, no HTTPS | SSO, short-lived tokens, TLS at a reverse proxy, rate limiting, key rotation |
| The model call blocks a worker for 20 to 40 s | A background queue with a status endpoint, or streaming |
| Events are not stored, and the baseline comes from each batch | Store events, keep per-user and per-service baselines, and backfill history |
| Streamlit dashboard | A real front end behind authentication, with automatic refresh and pagination |
| Secrets in a local .env file | A secrets manager |
| No saved or versioned ML model | If Isolation Forest were deployed: a model registry, recorded library versions, hash checks before loading (joblib files are pickle), and drift monitoring |
| CI uses the floating ubuntu-latest label and shows a Node.js deprecation warning | Pin the runner label and update the actions to their current versions |
| Automated browser tests | A browser test that checks hostile text renders as literal text |

## Monitoring plan (not built)
- **Service health:** request rate, latency percentiles, 5xx rate, model call latency and failure rate.
- **Detection health:** alerts per day, per scenario and per service. A sudden jump or drop means the data or the behaviour changed.
- **Analyst feedback:** the share of alerts closed as false_positive is already stored. Track it per signal, then use it to recalibrate the risk-score weights.
- **Data drift:** distribution of flow counts and failure rates per service compared with the baseline period.
- **Concept drift:** new attacker behaviour that no rule matches, noticed through analysts escalating alerts the system scored low.
- **LLM health:** the share of explanations failing validation, plus a weekly sample reviewed by an analyst.
- **Triggers:** recalibrate or retrain when the false-positive share or the alert rate moves outside an agreed band.

## Known limitations of the system
- Lab data with one scripted attacker. Results show that the method works, not that thresholds transfer to real traffic.
- The login detections were tested on a synthetic 18-row file and on unit tests, not on real traffic.
- The flow baseline uses labels to find benign windows. In production it would come from a known-clean period.
- The AI explanation is an unverified draft. It was tested on a handful of cases with one small local model, and the validator checks consistency with the evidence, not correctness.
- Each ingest batch is analysed alone, so there is no memory across batches.
- Ingest skips an alert it has already stored, so a later batch cannot raise an existing alert's score.
- Authentication is demo-grade. The dashboard is for localhost only.
- No MCP server was built. The tool layer is plain Python.
