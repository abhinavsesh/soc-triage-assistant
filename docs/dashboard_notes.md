# Dashboard: design notes

## What it does
- Alert table sorted by risk, with filters for status, severity and minimum score.
- Alert detail: signals, score breakdown, MITRE tags (labelled as hypotheses), evidence, AI explanation with validation badge, status updates, response action proposals and approvals, and the audit history.

## Design choices
- The dashboard talks to the API only. Authentication, validation and the audit log stay in one place, and the UI cannot bypass them.
- Each analyst enters their own API key, held in session memory only. Two browser tabs with two keys demonstrate four-eyes approval.
- Text that came from logs is rendered with st.text, st.dataframe and st.json, never as markdown or HTML, because markdown can render links and load remote images.
- The UI hides the approve button from the proposer, but the API enforces the rule. The UI is a convenience, not the control.
- The explanation view states plainly that passing the automatic checks does not mean the explanation is correct.
- The explanation takes 20 to 40 seconds with a local model, so it is generated on demand and cached by the API.

## Limitations
- Streamlit has no built-in authentication or HTTPS. The dashboard is for localhost. Exposing it needs a reverse proxy with TLS and real login.
- The API key is typed per session. Production would use proper login, session expiry and key rotation.
- The status dropdown lists every other status and relies on the API to refuse invalid moves. Better: the API returns the allowed next statuses.
- No automatic refresh. Another analyst's changes appear only after a page interaction.
- Flow alerts have no tools or raw events behind them in the dashboard.
- Only the first 100 alerts are shown, with no pagination.
- Not tested with an automated browser test. The client is unit tested; the page was checked by hand.
