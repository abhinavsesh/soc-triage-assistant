# Do we need an agent? Design decision

## Decision
The core system is an LLM application with a fixed pipeline (detect, score, explain). The only agentic element is a bounded, read-only lookup stage before the explanation. There is no general agent loop, no multi-agent design, and the model never executes anything.

## Reasons a general agent was not used
1. The workflow is fixed and known in advance. The detectors already compute the evidence the explanation needs.
2. Determinism and testability: a fixed pipeline can be unit tested. An open-ended loop cannot be covered by tests in the same way.
3. Cost and latency: a local model takes about 20 seconds per call, and every extra loop round adds to that.
4. Attack surface: tool arguments and tool results are untrusted text that an attacker can influence through logs.
5. Evaluation: it is much harder to measure the reliability of a model that chooses its own steps.

## Where lookups can add value
When the needed data is not known up front, for example whether a login IP is new for a user, or what else an IP has touched. These answers are not in the alert packet.

## What was built
- Three read-only tools: user_history, ip_activity and is_known_ip, over an in-memory copy of the auth log.
- A ToolRunner as the only door between the model and the tools:
  - an allowlist of three named tools
  - a budget of three calls
  - placeholder-only arguments, so the model never sees or supplies real names
  - validated and pseudonymised output, with every other string redacted
  - an audit log
- The model's free text in the lookup stage is discarded. Only cleaned results are added to the evidence, then the existing explain and validate path runs.
- An approval queue: the model can only propose, a human other than the proposer decides, and execution is refused unless the action is approved. The executor is a dry run that only writes a log line.

## Results, round 1 (model: <FILL IN: model name>, 2 alerts, one run each, temperature 0)

| Alert | Mode | Tool calls | Valid | Seconds |
|---|---|---|---|---|
| user:bob | no tools | none | yes | 35.4 (probably includes model loading) |
| user:bob | with tools | is_known_ip twice, both failed (user argument missing) | yes | 36.7 |
| ip:198.51.100.23 | no tools | none | yes | 18.8 |
| ip:198.51.100.23 | with tools | ip_activity, succeeded | no (citation format) | 37.1 |

Findings:
- Lookups added one concrete fact to one of two alerts: "4 failed attempts from 4 distinct users" from ip_activity, which is not in the alert packet. It matches the sample data. The validator does not check numbers in free text, so this match was not verified by the system.
- On user:bob the model called is_known_ip twice with only the ip argument. The error it received said only "wrong arguments", and it repeated the mistake. The summary used no tool data.
- The spraying run with tools was flagged invalid because the model cited the signals field as a comma-joined string instead of a list. Both values are in the evidence, so this is checker strictness, not a hallucination. It was left unfixed on purpose, to avoid tuning the checker on the same cases again.
- Latency: roughly 2x on the spraying alert (18.8 s to 37.1 s). The lookup itself took about 4-5 s from the log timestamps. The final explanation was slower because tool results lengthen the prompt.
- The model used placeholders correctly in every argument it supplied. The runner would have rejected anything else.
- Approval gate demo: executing before approval was refused, the model approving was refused, and a human approval followed by execution ran as a dry run. The status "executed" means a dry run. No system was changed.

## Round 2 (after the error message names the missing parameters)
<FILL IN: did the model retry correctly on user:bob, what did the lookup add, and what was the validity and latency? If round 2 was not run, write "Not run.">

## Conclusion
<FILL IN. Round 1 alone suggests marginal value on this data: one of two alerts gained a fact, the other gained nothing, and latency roughly doubled. That supports keeping the lookup stage optional and off by default.>

## MCP (concept level only, not implemented)
An MCP server was not built in this project. This section records my understanding of the protocol and why it affects the design.

- MCP is an open protocol for connecting an LLM application (the host) to external tools and data. The host runs one client per server. Servers expose tools (actions the model can request), resources (data) and prompts (templates). Messages are JSON-RPC, sent over stdio (a local subprocess) or streamable HTTP (remote).
- Why it exists: one standard interface instead of a custom integration for every application and every tool.
- Relation to this project: the ToolRunner plays the same role that an MCP server's tool layer would. It exposes a fixed set of named tools with typed arguments, and everything the model can do passes through it. Moving the same tools behind MCP would change the transport, not the safety requirements.
- Risks: tool descriptions and tool results are untrusted input (tool poisoning, indirect injection). Third-party servers can be malicious or over-privileged. A server with write access turns a hijacked model into a real action (OWASP LLM excessive agency).
- Mitigations: least privilege, an allowlist of servers, pinned versions, human approval for any sensitive tool, audit logs, and no execute tool exposed at all.
- MCP SDK details change between versions, so any implementation would need to be checked against the current documentation.

## Limitations
- The approver identity is a plain string. Real authentication must come from a session in the backend.
- The approval queue is in memory and is not persisted yet.
- Users whose names were altered by sanitising cannot be looked up, because the tools match on the original value. A real system would carry a separate stable identifier.
- A small local model's tool calling is less reliable than a hosted model's.
- The lookups cover only the auth log. Flow alerts have no tools.
- Two alerts and one run each: no rate can be stated, and the rounds are not independent samples.
- The numbers in a summary are not checked by the validator, so a correct figure from a tool result is not proof of verification.
- The error message was changed after seeing round 1, which is tuning on the evaluation cases. Both rounds are kept for that reason.
- MCP was studied at concept level only. No MCP server or client was built or tested.

## Interview answers in short
- Why not an agent: the workflow is fixed, the evidence is precomputed, and an agent adds latency, nondeterminism and attack surface.
- What stops a dangerous tool call: the model only emits a request. The runner allows three named read-only tools, requires placeholder arguments, enforces a budget, and no tool can write.
- What the approval gate does not do: it does not authenticate who the human is.
- Did you build an MCP server: no. I built the equivalent tool layer in plain Python and studied MCP at concept level, including its security risks.
