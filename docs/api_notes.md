# API and storage: design notes

## Endpoints
| Method and path | Purpose |
|---|---|
| GET /health | Liveness check, no key needed |
| POST /ingest/auth | Analyse a batch of auth events and store alerts (max 5000 events) |
| GET /alerts | List alerts by risk, with status, severity, min_score, limit, offset filters |
| GET /alerts/{id} | Alert detail with evidence, MITRE tags, latest explanation and history |
| PATCH /alerts/{id}/status | Analyst status change, with an allowed-transition table |
| POST /alerts/{id}/explain | Local-model explanation, cached, refresh=true to redo |
| POST /alerts/{id}/actions | Propose a response action (pending, nothing happens) |
| GET /actions | List proposals |
| POST /actions/{id}/decision | A human other than the proposer approves or rejects |
| POST /actions/{id}/execute | Dry run of an approved action. No system is changed |

## Design choices
- FastAPI with Pydantic models. Requests reject unknown fields and wrong types (422). Response models are an output whitelist.
- Plain sqlite3 with parameterised queries only. CHECK constraints and foreign keys enforce rules in the database too. WAL mode lets the dashboard read while the API writes.
- Each analyst has an API key, and the key determines the identity used for approvals and the audit log. The approver can never be the proposer or the model.
- Status changes use optimistic concurrency, so two analysts cannot silently overwrite each other (409).
- Execution flips status atomically, so an action cannot run twice.
- Ingest is idempotent per (entity, kind, first_seen).
- Errors: domain errors map to 400, 403, 404 or 409. An unavailable model returns 503. Anything unexpected returns a generic 500 with a request id, and the stack trace stays in the server log.
- Logs record method, path, status and timing only. Bodies, query strings and usernames are never logged, which also prevents log forging.
- Hostile usernames are truncated and have control characters replaced, then stored as data. They are not rejected, because rejecting a batch would let an attacker erase their own evidence.

## Limitations
- Authentication is demo-grade: static keys, no HTTPS, no rotation, no rate limiting.
- Every ingest request is analysed on its own. Events are not stored, and the new-IP baseline comes from that batch only.
- A re-ingested alert is skipped, so a later batch cannot raise an existing alert's score.
- The model call blocks a worker thread for about 20 seconds. A production system would use a background queue.
- The explanation endpoint does not use the Phase 7 lookups, because the raw auth log is not kept.
- Stored explanations contain real names restored from placeholders, and usernames are attacker-controlled. The dashboard must escape everything it displays.
- SQLite allows one writer at a time. Postgres would replace it at scale, with migrations instead of CREATE IF NOT EXISTS.
- Only auth events can be ingested through the API. Flow alerts are loaded by a script.
