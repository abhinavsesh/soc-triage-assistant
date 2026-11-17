# Security review

Review date: 2026-11-16.
Scope: the whole application running locally (API, SQLite, dashboard, local model). Reviewed against threats an attacker can cause through log content, API requests and the AI components. Exact OWASP LLM Top 10 and MITRE ATLAS numbering and technique names should be checked on their current pages.

## Trust boundaries
- Log data (usernames, IPs, timestamps) is attacker-influenced: untrusted.
- Model output is untrusted until validated, and even validated output is a draft.
- Analysts authenticate with an API key. Code behind the API is trusted.

## Threats and controls
| Threat | Controls | Residual risk |
|---|---|---|
| Prompt injection through log fields (indirect) | Field whitelist, typed-field validation (IP fields must be IPs), sanitising and length cap, pseudonymisation, delimited evidence, JSON output validated against the evidence | Instructions made of ordinary words survive in free text. Raw mode exposes usernames. Tested on a handful of cases only |
| Direct prompt injection | No free-text chat with the model. Analysts cannot send prompts | None identified |
| Sensitive data sent to a model | Local model. Usernames and IPs replaced by placeholders before the prompt | Names are restored for display, so stored explanations contain real names |
| Excessive agency | The model has no write tools. Lookups are read-only, allowlisted and budgeted. Actions are proposals needing a different human to approve. Execution is a dry run | Approver identity depends on API key handling |
| Insecure output handling (dashboard) | Log-derived text is rendered with st.text, st.dataframe and st.json, never as markdown or HTML | Not tested with an automated browser |
| SQL injection | Parameterised queries only. CHECK constraints. Filters validated by Pydantic | Fixed SQL fragments are concatenated in list_alerts (see bandit below) |
| Log forging | Control characters replaced in usernames. Request logs never contain bodies, query strings or usernames. Audit details are our own text | Stored username text is still attacker-chosen |
| Authentication bypass | Every route except /health needs a key. Constant-time comparison. Fails closed (503) if no keys are configured | Static keys, no HTTPS, no rotation, no rate limiting |
| Denial of service | Batch size capped at 5000, field length limits, pagination caps | One request can still occupy a worker for the model call. No rate limiting |
| Hiding an attack with a hostile event | Hostile usernames are truncated and kept as data, not rejected | Fully malformed events are rejected with 422 and not quarantined |
| Poisoned baseline | Baseline computed from benign windows only | An attacker active while the baseline is learned becomes normal. In the lab data, labels select the baseline rows |
| Supply chain (dependencies, model files) | Pinned requirements. pip-audit run. No model file is loaded from an untrusted source | joblib files are pickle, and loading an untrusted one can run code. No model is currently saved |
| Hallucination and misinformation | Output checked against the evidence. The UI says it is a draft that passed consistency checks | The validator cannot check interpretation, numbers in free text, or wrong claims such as calling a risk score a confidence |
| Audit tampering | Audit rows are written in the same transaction as each change | Anyone with disk access can edit the SQLite file |

## Findings during development that changed the design
1. Failures were first counted per user across all IPs, so a success from a new IP could qualify because of failures from a different IP. Found in review. Changed to per (user, IP) with tests that failed against the old code.
2. Evidence for a repeated scenario was overwritten when incidents merged. Changed to accumulate a list of observations.
3. Inspecting the packet sent to the model showed that instruction text placed in an IP field survived pseudonymisation, because only the valid IP part was replaced. The model did not obey it, but the fix was not to rely on that: IP fields are now validated and replaced with a fixed token if invalid.
4. The output validator flagged correct answers (list-valued and dotted citations) and misses wrong interpretations. The false positives were fixed. The blind spots are listed above.

## Checks performed
- Secrets and data files in Git: a filtered git ls-files (.env, *.db, *.joblib, data/raw, data/processed), a history search for .env, and a history search for key values all returned nothing. .env.example contains placeholders only.
- pip-audit on requirements.txt: <FILL IN: "No known vulnerabilities found." or the packages reported and what was done about each>
- bandit on src (1,709 lines): one finding, medium severity and low confidence, in list_alerts at db.py:186 (SQL built from strings). False positive: only fixed fragments are joined and every value is a bound parameter. No other findings.
- Live API checks against the running server: no key gave 401, a non-integer id gave 422, a SQL-looking status filter gave 422, an empty events list gave 422.
- Dashboard markdown check: a username containing a markdown image, a link and bold text was ingested through the API. In the alert table, the entity line and the evidence tab it appeared as literal text, with no image request, no clickable link and no bold.
- Tests: 113 pass locally, including hostile-username, SQL-looking input, log-forging, authorisation and four-eyes approval cases. The GitHub Actions run is green.
- Timing: ingest of 4,907 events took 0.48 s in one in-process run. Alert listing took 4 ms.

## Known issues from tooling
- CI uses the floating ubuntu-latest label, which GitHub is migrating to a newer Ubuntu, so the environment can change without a code change. Pin a runner label to fix. The checkout and setup-python actions also show a Node.js deprecation warning.
- Starlette reports that using httpx with its test client is deprecated. Tests pass today. Versions should be pinned and the test client dependency revisited on upgrade.

## Not done
- HTTPS, key rotation, SSO, rate limiting, a web application firewall.
- Automated browser tests, fuzzing, a penetration test.
- A secrets manager. Keys are in a local .env file.
