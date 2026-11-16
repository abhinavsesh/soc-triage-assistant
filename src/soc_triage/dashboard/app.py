"""Streamlit dashboard. It talks to the API only: no database access, no model calls.
Anything that came from logs is untrusted text. Render it with st.text, st.dataframe or st.json,
never as markdown or HTML (markdown can load remote images and render links)."""
import os

import pandas as pd
import streamlit as st

from soc_triage.dashboard.client import ApiClient, ApiError

API_URL = os.getenv("DASHBOARD_API_URL", "http://127.0.0.1:8000")
STATUSES = ["new", "investigating", "false_positive", "escalated", "closed"]
STATUS_FILTER = ["any"] + STATUSES
SEVERITY_FILTER = ["any", "low", "medium", "high"]
ACTIONS = ["block_ip", "reset_password", "disable_account"]

st.set_page_config(page_title="SOC Alert Triage", layout="wide")
st.title("SOC Alert Triage Assistant")


def api():
    return ApiClient(API_URL, st.session_state.get("api_key", ""))


def call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ApiError as e:
        st.error(f"API error ({e.status}): {e.detail}")
        return None


def flash(message):
    st.session_state["flash"] = message
    st.rerun()


def show_explanation(ex):
    if ex["ok"]:
        st.success("Passed the automatic checks against the evidence. That does not mean it is correct.")
    else:
        st.warning("Failed the automatic checks. Do not rely on this explanation without checking the evidence.")
        for p in ex["problems"]:
            st.text(f"- {p}")
    e = ex.get("explanation") or {}
    st.subheader("Summary")
    st.text(str(e.get("summary", "")))
    st.subheader("Investigation steps (read-only)")
    for s in e.get("investigation_steps", []):
        st.text(f"- {s}")
    st.subheader("MITRE hypotheses")
    for h in e.get("mitre_hypotheses", []):
        st.text(f"{h.get('id')}: {h.get('reasoning')}")
    st.subheader("Proposed actions (the model can only propose)")
    for a in e.get("proposed_actions", []):
        st.text(f"- {a}")
    st.subheader("What the evidence cannot tell us")
    st.text(str(e.get("uncertainty", "")))
    st.text(f"Model: {ex['model']} | {ex['seconds']} s | requested by {ex['requested_by']} | {ex['created_at']}")


# ---------- sign-in ----------
with st.sidebar:
    st.header("Analyst sign-in")
    if st.session_state.get("analyst"):
        st.text(f"Signed in as {st.session_state['analyst']}")
        if st.button("Sign out"):
            st.session_state.clear()
            st.rerun()
    else:
        key = st.text_input("API key", type="password")
        if st.button("Sign in"):
            st.session_state["api_key"] = key
            who = call(api().me)
            if who:
                st.session_state["analyst"] = who["analyst"]
                st.rerun()
            st.session_state["api_key"] = ""
    st.caption("The key stays in this browser session's memory only.")

me = st.session_state.get("analyst")
if not me:
    st.info("Sign in with your analyst API key in the sidebar.")
    st.stop()

if st.session_state.get("flash"):
    st.success(st.session_state.pop("flash"))

# ---------- alert table (Task 36) ----------
f1, f2, f3 = st.columns(3)
status_f = f1.selectbox("Status", STATUS_FILTER)
severity_f = f2.selectbox("Severity", SEVERITY_FILTER)
min_score = f3.slider("Minimum risk score", 0, 100, 0)

alerts = call(api().alerts,
              status=None if status_f == "any" else status_f,
              severity=None if severity_f == "any" else severity_f,
              min_score=min_score)
if not alerts:
    st.info("No alerts match these filters.")
    st.stop()

st.dataframe(pd.DataFrame(alerts)[["id", "risk_score", "severity", "status", "entity", "kind", "first_seen"]],
             hide_index=True)

alert_id = st.selectbox("Open alert", [a["id"] for a in alerts])
d = call(api().alert, alert_id)
if d is None:
    st.stop()

# ---------- alert detail (Task 37) ----------
st.subheader("Alert detail")
st.text(f"Entity: {d['entity']}")
m1, m2, m3 = st.columns(3)
m1.metric("Risk score", d["risk_score"])
m2.metric("Severity", d["severity"])
m3.metric("Status", d["status"])
st.text(f"First seen: {d['first_seen']}")

tab_ev, tab_ai, tab_status, tab_actions, tab_hist = st.tabs(
    ["Evidence", "AI explanation", "Status", "Response actions", "History"])

with tab_ev:
    st.text("Signals: " + ", ".join(d["signals"]))
    st.text("Score breakdown (points per signal). The score ranks urgency. It is not a probability.")
    st.dataframe(pd.DataFrame(list(d["score_breakdown"].items()), columns=["signal", "points"]),
                 hide_index=True)
    if d["mitre"]:
        st.text("MITRE ATT&CK tags are hypotheses from fixed rules, not confirmed techniques.")
        st.dataframe(pd.DataFrame(d["mitre"])[["id", "name", "tactic", "confidence"]], hide_index=True)
    st.json(d["evidence"])

with tab_ai:
    st.text("AI-generated draft. Check it against the Evidence tab. It cannot take any action.")
    ex = d["explanation"]
    label = "Generate explanation" if ex is None else "Regenerate explanation"
    if st.button(label):
        with st.spinner("Asking the local model (about 20 to 40 seconds)..."):
            fresh = call(api().explain, alert_id, refresh=ex is not None)
        if fresh:
            ex = fresh
    if ex:
        show_explanation(ex)
    else:
        st.info("No explanation yet.")

# ---------- status updates (Task 38) ----------
with tab_status:
    with st.form("status_form"):
        new_status = st.selectbox("New status", [s for s in STATUSES if s != d["status"]])
        note = st.text_input("Note (optional)", max_chars=500)
        if st.form_submit_button("Update status"):
            if call(api().set_status, alert_id, new_status, note or None):
                flash(f"Status changed to {new_status}")
    st.text("The server decides which moves are allowed and will refuse the others.")

with tab_actions:
    st.text("Nothing here changes a real system. Execution is a dry run. Approval needs a different analyst from the proposer.")
    acts = [a for a in (call(api().actions) or []) if a["alert_id"] == alert_id]
    if acts:
        st.dataframe(pd.DataFrame(acts)[["id", "action", "target", "status", "proposed_by", "decided_by", "reason"]],
                     hide_index=True)
    for a in acts:
        if a["status"] == "pending" and a["proposed_by"] != me:
            c1, c2 = st.columns(2)
            if c1.button(f"Approve #{a['id']}", key=f"approve{a['id']}"):
                if call(api().decide, a["id"], "approve"):
                    flash(f"Action #{a['id']} approved")
            if c2.button(f"Reject #{a['id']}", key=f"reject{a['id']}"):
                if call(api().decide, a["id"], "reject"):
                    flash(f"Action #{a['id']} rejected")
        elif a["status"] == "pending":
            st.text(f"Action #{a['id']} is waiting for a different analyst to decide.")
        elif a["status"] == "approved":
            if st.button(f"Execute #{a['id']} (dry run)", key=f"execute{a['id']}"):
                if call(api().execute, a["id"]):
                    flash(f"Action #{a['id']} executed as a dry run")
    with st.form("propose_form"):
        action = st.selectbox("Action to propose", ACTIONS)
        target = st.text_input("Target (an IP address or a username)", max_chars=64)
        reason = st.text_area("Reason", max_chars=500)
        if st.form_submit_button("Propose"):
            if call(api().propose, alert_id, action, target, reason):
                flash("Action proposed. It is pending until another analyst approves it.")

with tab_hist:
    if d["history"]:
        st.dataframe(pd.DataFrame(d["history"]), hide_index=True)
    else:
        st.text("No history yet.")
