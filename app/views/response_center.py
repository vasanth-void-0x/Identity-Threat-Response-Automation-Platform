"""Tabbed response workspace with safe simulation and dual approval."""

from __future__ import annotations

import streamlit as st

from app.components.tables import render_response_actions_table
from app.theme import page_header
from app.utils.data_mode import filter_incidents
from automation.response_engine import approve_action, execute_action, reject_action, request_real_action
from core.config import load_config
from core.exceptions import ResponseActionError
from database import repository


def render() -> None:
    policy = load_config().response_policy
    page_header("Response Center", "Analyst-controlled simulation, dual approval and complete response audit history.")
    st.caption(
        f"Policy · {'SIMULATION SAFE' if policy.simulation_mode else 'REAL ACTIONS ENABLED'} · "
        f"Approval {'required' if policy.require_analyst_approval else 'not required'}"
    )
    all_alerts = repository.get_alerts(limit=5000)
    incidents = filter_incidents(
        repository.get_incidents(limit=200), all_alerts, st.session_state.get("data_mode", "Live Splunk")
    )
    incident_ids = [item["incident_id"] for item in incidents]

    pending = st.session_state.pop("_prefill_sim_incident", None)
    if pending and pending in incident_ids and st.session_state.get("sim_incident") != pending:
        st.session_state["sim_incident"] = pending

    simulation_tab, approval_tab, history_tab = st.tabs(["Simulated action", "Pending approvals", "Action history"])

    with simulation_tab:
        st.caption("Executes immediately in simulation only; no account, host or network is changed.")
        col1, col2, col3 = st.columns(3)
        with col1:
            incident_id = st.selectbox("Incident", ["-- select --"] + incident_ids, key="sim_incident")
        with col2:
            action_type = st.selectbox("Action", policy.action_allowlist, key="sim_action")
        with col3:
            target = st.text_input("Target", key="sim_target", placeholder="IP / username / host / PID")
        if st.button("Execute simulated action", type="primary"):
            if incident_id == "-- select --" or not target:
                st.warning("Select an incident and provide a target.")
            else:
                incident = repository.get_incident(incident_id)
                action = execute_action(
                    incident_id=incident_id,
                    action_type=action_type,
                    target=target,
                    severity=incident["severity"],
                    requested_by=st.session_state.get("analyst_name", "analyst"),
                    real_mode=False,
                )
                (st.error if action.status == "failed" else st.success)(action.result)

        with st.expander("Request a real action · second analyst approval required"):
            if policy.simulation_mode:
                st.info("Real requests are blocked while simulation mode is enabled.")
            r1, r2, r3 = st.columns(3)
            with r1:
                real_incident = st.selectbox("Incident", ["-- select --"] + incident_ids, key="real_incident")
            with r2:
                real_action = st.selectbox("Action", policy.action_allowlist, key="real_action")
            with r3:
                real_target = st.text_input("Target", key="real_target")
            if st.button("Submit approval request"):
                if real_incident == "-- select --" or not real_target:
                    st.warning("Select an incident and provide a target.")
                else:
                    incident = repository.get_incident(real_incident)
                    action = request_real_action(
                        incident_id=real_incident,
                        action_type=real_action,
                        target=real_target,
                        severity=incident["severity"],
                        requested_by=st.session_state.get("analyst_name", "analyst"),
                    )
                    (st.error if action.status == "failed" else st.success)(action.result)

    with approval_tab:
        pending = repository.get_response_actions(status="pending_approval")
        if not pending:
            st.info("No response actions awaiting approval.")
        else:
            approver = st.text_input(
                "Approving analyst", value=st.session_state.get("analyst_name", ""), key="approver_name"
            )
            for item in pending:
                with st.container(border=True):
                    st.write(
                        f"**{item['action_type']}** · `{item['target']}` · `{item['incident_id']}` · "
                        f"requested by `{item['requested_by']}`"
                    )
                    approve_col, reject_col = st.columns(2)
                    with approve_col:
                        if st.button("Approve", key=f"approve_{item['action_id']}"):
                            try:
                                result = approve_action(item["action_id"], approver or "")
                                (st.success if result.status == "executed" else st.error)(result.result)
                                st.rerun()
                            except ResponseActionError as exc:
                                st.error(str(exc))
                    with reject_col:
                        if st.button("Reject", key=f"reject_{item['action_id']}"):
                            try:
                                reject_action(item["action_id"], approver or "unknown", "Rejected via dashboard")
                                st.rerun()
                            except ResponseActionError as exc:
                                st.error(str(exc))

    with history_tab:
        status = st.segmented_control("Status", ["All", "Pending", "Executed", "Failed"], default="All")
        mapping = {"Pending": "pending_approval", "Executed": "executed", "Failed": "failed"}
        render_response_actions_table(repository.get_response_actions(status=mapping.get(status)), height=480)
