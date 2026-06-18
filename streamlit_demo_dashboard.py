"""Streamlit demo app for AC.L2-3.1.1 evidence verification."""

from __future__ import annotations

import csv
import hashlib
import html
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import streamlit as st

from ncat_verifier import _read_csv_rows, verify_packet, write_outputs
from generate_remediation_with_openai import generate_remediation_markdown


st.set_page_config(
    page_title="NexGen CMMC Level 2 Verifier - AC.L2-3.1.1",
    page_icon="N",
    layout="wide",
)


def _inject_global_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
            --bg: #f6f7fb;
            --panel: #ffffff;
            --panel-soft: #f8fafc;
            --ink: #172033;
            --muted: #667085;
            --line: #d9e0ea;
            --blue: #1f6feb;
            --action: #1f6feb;
            --action-dark: #1a5dcc;
            --teal: #0f766e;
            --green: #16835b;
            --red: #c43d3d;
            --amber: #b87514;
            --purple: #6941c6;
        }
        .stApp {
            background:
                linear-gradient(180deg, #f8fbff 0%, var(--bg) 36%, #eef2f6 100%);
            color: var(--ink);
        }
        .block-container {
            padding-top: 2.2rem;
            padding-bottom: 3rem;
            max-width: 1280px;
        }
        h1, h2, h3 {
            color: var(--ink);
            letter-spacing: 0;
        }
        [data-testid="stSidebar"] {
            background: #101828;
            color: #f8fafc;
        }
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] span {
            color: #e4e7ec;
        }
        [data-testid="stMetric"] {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 1rem;
            box-shadow: 0 10px 24px rgba(16, 24, 40, 0.05);
        }
        [data-testid="stMetricLabel"] {
            color: var(--muted);
        }
        [data-testid="stButton"] button {
            border-radius: 8px;
            border: 1px solid #cfd7e3;
            font-weight: 650;
            min-height: 2.55rem;
        }
        [data-testid="stButton"] button[kind="primary"] {
            background: var(--action);
            border-color: var(--action);
            color: #ffffff;
        }
        [data-testid="stButton"] button[kind="primary"]:hover {
            background: var(--action-dark);
            border-color: var(--action-dark);
            color: #ffffff;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 0.5rem;
            border-bottom: 0;
        }
        .stTabs [data-baseweb="tab"] {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            color: #344054;
            font-weight: 750;
            height: 2.55rem;
            padding: 0 1rem;
        }
        .stTabs [data-baseweb="tab"]:hover {
            background: #f8fafc;
            border-color: #98a2b3;
            color: #1d2939;
        }
        .stTabs [data-baseweb="tab"][aria-selected="true"] {
            background: var(--action);
            border-color: var(--action);
            color: #ffffff;
        }
        .stTabs [data-baseweb="tab"] p {
            font-weight: 750;
        }
        .stTabs [data-baseweb="tab"][aria-selected="true"] p {
            color: #ffffff;
        }
        .hero {
            border: 1px solid #cfd9e8;
            border-radius: 8px;
            padding: 1.45rem 1.6rem;
            background:
                linear-gradient(135deg, rgba(31, 111, 235, 0.10), rgba(15, 118, 110, 0.08)),
                #ffffff;
            box-shadow: 0 16px 40px rgba(16, 24, 40, 0.08);
            margin-bottom: 1.1rem;
        }
        .eyebrow {
            color: var(--blue);
            font-size: 0.78rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 0.3rem;
        }
        .hero h1 {
            font-size: 2.25rem;
            line-height: 1.08;
            margin: 0;
        }
        .hero p {
            color: #475467;
            font-size: 1.02rem;
            line-height: 1.55;
            max-width: 820px;
            margin: 0.75rem 0 0;
        }
        .proof-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 0.8rem;
            margin: 0.9rem 0 1.2rem;
        }
        .proof-card,
        .summary-card,
        .action-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 1rem;
            box-shadow: 0 10px 24px rgba(16, 24, 40, 0.05);
        }
        .proof-card strong,
        .summary-card strong,
        .action-card strong {
            display: block;
            color: var(--ink);
            font-size: 0.95rem;
            margin-bottom: 0.28rem;
        }
        .proof-card span,
        .summary-card span,
        .action-card span {
            color: var(--muted);
            font-size: 0.86rem;
            line-height: 1.4;
        }
        .status-strip {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 1rem 1.1rem;
            margin: 0.3rem 0 1rem;
            box-shadow: 0 10px 24px rgba(16, 24, 40, 0.05);
        }
        .status-strip h3 {
            margin: 0;
            font-size: 1.1rem;
        }
        .status-strip p {
            margin: 0.2rem 0 0;
            color: var(--muted);
            font-size: 0.9rem;
        }
        .pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 7.5rem;
            border-radius: 999px;
            padding: 0.45rem 0.8rem;
            font-size: 0.82rem;
            font-weight: 800;
            letter-spacing: 0.04em;
        }
        .pill-green {
            color: #067647;
            background: #dcfae6;
            border: 1px solid #abefc6;
        }
        .pill-red {
            color: #b42318;
            background: #fee4e2;
            border: 1px solid #fecdca;
        }
        .pill-amber {
            color: #93370d;
            background: #fef0c7;
            border: 1px solid #fedf89;
        }
        .monitor-bar {
            background: #ffffff;
            border: 1px solid var(--line);
            border-left: 5px solid var(--teal);
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            box-shadow: 0 10px 24px rgba(16, 24, 40, 0.05);
        }
        .monitor-bar strong {
            color: var(--ink);
        }
        .monitor-bar span {
            color: var(--muted);
            font-size: 0.88rem;
        }
        .mini-label {
            color: var(--muted);
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            font-weight: 800;
            margin-bottom: 0.25rem;
        }
        .section-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .readiness-grid {
            display: grid;
            grid-template-columns: minmax(0, 1.28fr) minmax(320px, 0.72fr);
            gap: 1rem;
            margin: 0.8rem 0 1rem;
        }
        .readiness-panel,
        .queue-panel,
        .pipeline-panel,
        .comparison-panel {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 1rem;
            box-shadow: 0 10px 24px rgba(16, 24, 40, 0.05);
        }
        .panel-title {
            display: flex;
            justify-content: space-between;
            gap: 1rem;
            align-items: baseline;
            border-bottom: 1px solid #eef2f6;
            padding-bottom: 0.75rem;
            margin-bottom: 1rem;
        }
        .panel-title h3 {
            margin: 0;
            font-size: 1.15rem;
        }
        .panel-title span {
            color: var(--muted);
            font-size: 0.86rem;
        }
        .objective-wrap {
            display: grid;
            grid-template-columns: 230px minmax(0, 1fr);
            gap: 1rem;
            align-items: center;
        }
        .donut {
            width: 210px;
            height: 210px;
            border-radius: 50%;
            display: grid;
            place-items: center;
            position: relative;
            margin: 0 auto;
            box-shadow: inset 0 0 0 1px rgba(16, 24, 40, 0.06);
        }
        .donut::before {
            content: "";
            position: absolute;
            width: 142px;
            height: 142px;
            border-radius: 50%;
            background: #ffffff;
            box-shadow: 0 0 0 1px #eef2f6;
        }
        .donut-center {
            position: relative;
            text-align: center;
        }
        .donut-center strong {
            display: block;
            color: var(--ink);
            font-size: 2rem;
            line-height: 1;
        }
        .donut-center span {
            color: var(--muted);
            font-size: 0.85rem;
            font-weight: 700;
        }
        .objective-list {
            display: grid;
            gap: 0.55rem;
        }
        .objective-row {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 0.75rem;
            align-items: center;
            padding: 0.58rem 0.7rem;
            border: 1px solid #eef2f6;
            border-radius: 8px;
            background: #fcfcfd;
        }
        .objective-row strong {
            color: #344054;
            font-size: 0.9rem;
            font-weight: 750;
        }
        .tiny-pill {
            border-radius: 999px;
            padding: 0.18rem 0.52rem;
            font-size: 0.72rem;
            font-weight: 850;
            letter-spacing: 0.03em;
            white-space: nowrap;
        }
        .tiny-green {
            background: #dcfae6;
            color: #067647;
            border: 1px solid #abefc6;
        }
        .tiny-red {
            background: #fee4e2;
            color: #b42318;
            border: 1px solid #fecdca;
        }
        .tiny-amber {
            background: #fef0c7;
            color: #93370d;
            border: 1px solid #fedf89;
        }
        .tiny-gray {
            background: #f2f4f7;
            color: #475467;
            border: 1px solid #e4e7ec;
        }
        .queue-list {
            display: grid;
            gap: 0.55rem;
        }
        .queue-item {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 0.75rem;
            align-items: center;
            padding: 0.72rem 0;
            border-bottom: 1px solid #eef2f6;
        }
        .queue-item:last-child {
            border-bottom: 0;
        }
        .queue-item strong {
            display: block;
            color: #344054;
            font-size: 0.92rem;
        }
        .queue-item span {
            color: var(--muted);
            font-size: 0.8rem;
        }
        .queue-arrow {
            color: var(--action);
            font-size: 1.35rem;
            font-weight: 800;
            text-decoration: none;
            line-height: 1;
            padding: 0.2rem 0.35rem;
            border-radius: 6px;
        }
        .queue-arrow:hover {
            background: #eff6ff;
            color: var(--action-dark);
        }
        .pipeline {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 0.75rem;
        }
        .pipeline-step {
            border: 1px solid #e4e7ec;
            border-radius: 8px;
            padding: 0.85rem;
            background: #fcfcfd;
        }
        .pipeline-step strong {
            display: block;
            color: var(--ink);
            font-size: 0.92rem;
            margin-bottom: 0.25rem;
        }
        .pipeline-step span {
            color: var(--muted);
            font-size: 0.82rem;
            line-height: 1.38;
        }
        .comparison-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 0.75rem;
        }
        .comparison-cell {
            border: 1px solid #e4e7ec;
            border-radius: 8px;
            background: #fcfcfd;
            padding: 0.8rem;
        }
        .comparison-cell strong {
            color: var(--ink);
            display: block;
            font-size: 1.12rem;
            margin-bottom: 0.2rem;
        }
        .comparison-cell span {
            color: var(--muted);
            font-size: 0.82rem;
            line-height: 1.35;
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid var(--line);
            border-radius: 8px;
            overflow: hidden;
        }
        @media (max-width: 900px) {
            .proof-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .status-strip {
                align-items: flex-start;
                flex-direction: column;
            }
            .readiness-grid,
            .objective-wrap,
            .pipeline,
            .comparison-grid {
                grid-template-columns: 1fr;
            }
            .hero h1 {
                font-size: 1.8rem;
            }
        }
        @media (max-width: 640px) {
            .proof-grid {
                grid-template-columns: 1fr;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _init_session_state() -> None:
    st.session_state.setdefault("ncat_running", False)
    st.session_state.setdefault("ncat_packet_dir", "")
    st.session_state.setdefault("ncat_source_dir", "")
    st.session_state.setdefault("ncat_event_log", [])
    st.session_state.setdefault("llm_attempted_signatures", set())


def _dashboard_severity(finding: dict[str, str]) -> str:
    raw = finding.get("severity", "info").lower()
    message = finding.get("message", "")
    if raw == "high" and "Unauthorized device" in message:
        return "medium"
    return raw


def _root_cause_bucket(finding: dict[str, str]) -> str:
    message = finding.get("message", "")
    if "Unauthorized user" in message or "Guest/external user" in message:
        return "Unauthorized user access"
    if "device" in message.lower():
        return "Device policy mismatch"
    if "process/app" in message:
        return "Unauthorized process access"
    if "does not exist" in message:
        return "Unknown identity reference"
    return "Other"


def _severity_badge(sev: str) -> str:
    s = sev.lower()
    if s == "high":
        return "HIGH"
    if s == "medium":
        return "MEDIUM"
    if s == "low":
        return "LOW"
    return "INFO"


def _status_class(status: str) -> str:
    if status == "MET":
        return "pill-green"
    if status == "NOT MET":
        return "pill-red"
    return "pill-amber"


def _status_label(status: str) -> str:
    if status == "MET":
        return "READY"
    if status == "NOT MET":
        return "ACTION REQUIRED"
    return "NOT APPLICABLE"


def _render_proof_cards() -> None:
    st.markdown(
        """
        <div class="proof-grid">
            <div class="proof-card">
                <strong>Level 2 control</strong>
                <span>AC.L2-3.1.1 mapped to CUI access objectives.</span>
            </div>
            <div class="proof-card">
                <strong>Multi-stack normalization</strong>
                <span>Microsoft CSV and Okta/Box/Jamf JSON feed one evidence model.</span>
            </div>
            <div class="proof-card">
                <strong>Deterministic core</strong>
                <span>Findings trace back to concrete evidence references.</span>
            </div>
            <div class="proof-card">
                <strong>Approval-gated action</strong>
                <span>Candidate API actions require IT/security approval.</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_summary_cards(result: dict[str, Any]) -> None:
    context = result.get("context", {})
    findings = result.get("findings", [])
    runtime = context.get("runtime_metrics", {})
    source_stack = html.escape(str(context.get("source_stack", "Unknown")))
    resource_name = html.escape(str(context.get("resource_name", "Unknown")))
    elapsed = html.escape(str(runtime.get("verification_elapsed_ms", 0)))
    effective = html.escape(str(context.get("effective_access_count", 0)))
    finding_count = html.escape(str(len(findings)))

    st.markdown(
        f"""
        <div class="proof-grid">
            <div class="summary-card">
                <div class="mini-label">Source stack</div>
                <strong>{source_stack}</strong>
                <span>Raw platform evidence normalized before verification.</span>
            </div>
            <div class="summary-card">
                <div class="mini-label">CUI resource</div>
                <strong>{resource_name}</strong>
                <span>Access is evaluated against the configured CUI scope.</span>
            </div>
            <div class="summary-card">
                <div class="mini-label">Verification time</div>
                <strong>{elapsed} ms</strong>
                <span>Deterministic time-to-finding for this representative packet.</span>
            </div>
            <div class="summary-card">
                <div class="mini-label">Effective users</div>
                <strong>{effective}</strong>
                <span>{finding_count} findings returned from objective checks.</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _objective_label(objective: str) -> str:
    labels = {
        "a_authorized_users_identified": "Authorized users identified",
        "b_authorized_processes_identified": "Authorized processes identified",
        "c_authorized_devices_identified": "Authorized devices identified",
        "d_access_limited_to_authorized_users": "Access limited to authorized users",
        "e_access_limited_to_authorized_processes": "Access limited to authorized processes",
        "f_access_limited_to_authorized_devices": "Access limited to authorized devices",
    }
    return labels.get(objective, objective.replace("_", " ").title())


def _tiny_status_class(status: str) -> str:
    if status == "MET":
        return "tiny-green"
    if status == "NOT MET":
        return "tiny-red"
    if status == "NOT ASSESSED":
        return "tiny-gray"
    return "tiny-amber"


def _render_objective_readiness(result: dict[str, Any]) -> None:
    objectives = result.get("context", {}).get("assessment_objectives", {})
    if not objectives:
        st.info("Assessment objectives were not returned for this evidence packet.")
        return

    total = len(objectives)
    met = sum(1 for status in objectives.values() if status == "MET")
    failed = sum(1 for status in objectives.values() if status == "NOT MET")
    met_pct = round((met / total) * 100) if total else 0
    green_end = (met / total) * 100 if total else 0
    red_end = ((met + failed) / total) * 100 if total else 0

    if total:
        gradient = (
            f"conic-gradient(#16835b 0 {green_end:.2f}%, "
            f"#c43d3d {green_end:.2f}% {red_end:.2f}%, "
            f"#d0d5dd {red_end:.2f}% 100%)"
        )
    else:
        gradient = "#d0d5dd"

    objective_rows = "".join(
        (
            '<div class="objective-row">'
            f"<strong>{html.escape(_objective_label(key))}</strong>"
            f'<span class="tiny-pill {_tiny_status_class(status)}">'
            f"{html.escape(status)}</span>"
            "</div>"
        )
        for key, status in objectives.items()
    )

    st.markdown(
        (
            '<div class="readiness-panel">'
            '<div class="panel-title">'
            "<h3>Implementation Status</h3>"
            "<span>AC.L2-3.1.1 objective readiness</span>"
            "</div>"
            '<div class="objective-wrap">'
            f'<div class="donut" style="background: {gradient};">'
            '<div class="donut-center">'
            f"<strong>{met_pct}%</strong>"
            f"<span>{met}/{total} objectives met</span>"
            "</div>"
            "</div>"
            f'<div class="objective-list">{objective_rows}</div>'
            "</div>"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def _render_action_queue(result: dict[str, Any]) -> None:
    findings = result.get("findings", [])
    proposed_actions = result.get("proposed_actions", [])
    if findings:
        bucket_counts = Counter(_root_cause_bucket(finding) for finding in findings)
        queue_rows = "".join(
            (
                '<div class="queue-item">'
                "<div>"
                f"<strong>{html.escape(category)}</strong>"
                f"<span>{count} finding{'s' if count != 1 else ''} awaiting review</span>"
                "</div>"
                '<a class="queue-arrow" href="#findings-jump-target" '
                'aria-label="Jump to evidence-linked findings">&rarr;</a>'
                "</div>"
            )
            for category, count in sorted(bucket_counts.items(), key=lambda item: item[0])
        )
        lead = f"{len(proposed_actions)} approval-gated candidate action"
        if len(proposed_actions) != 1:
            lead += "s"
    else:
        queue_rows = (
            '<div class="queue-item">'
            "<div>"
            "<strong>No remediation required</strong>"
            "<span>Current evidence satisfies the configured CUI access policy.</span>"
            "</div>"
            '<div class="queue-arrow">OK</div>'
            "</div>"
            '<div class="queue-item">'
            "<div>"
            "<strong>Run drift scenario</strong>"
            "<span>Inject a user or device issue to show time-to-finding.</span>"
            "</div>"
            '<div class="queue-arrow">&rarr;</div>'
            "</div>"
            '<div class="queue-item">'
            "<div>"
            "<strong>Export audit packet</strong>"
            "<span>Scorecard and report are generated after each run.</span>"
            "</div>"
            '<div class="queue-arrow">&rarr;</div>'
            "</div>"
        )
        lead = "No open findings"

    st.markdown(
        (
            '<div class="queue-panel">'
            '<div class="panel-title">'
            "<h3>To Do</h3>"
            f"<span>{html.escape(lead)}</span>"
            "</div>"
            f'<div class="queue-list">{queue_rows}</div>'
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def _findings_for_display(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    findings_for_display = []
    for finding in findings:
        normalized_severity = _dashboard_severity(finding)
        findings_for_display.append(
            {
                "severity": _severity_badge(normalized_severity),
                "root cause": _root_cause_bucket(finding),
                "finding": finding.get("message", ""),
                "evidence": finding.get("evidence_ref", ""),
            }
        )
    return findings_for_display


def _render_evidence_pipeline(result: dict[str, Any]) -> None:
    context = result.get("context", {})
    normalization = context.get("normalization_summary", {})
    source_stack = html.escape(str(context.get("source_stack", "Unknown")))
    raw_format = html.escape(str(normalization.get("raw_format", "Raw evidence exports")))
    users = html.escape(str(normalization.get("users", 0)))
    groups = html.escape(str(normalization.get("groups", 0)))
    devices = html.escape(str(normalization.get("devices", 0)))
    permissions = html.escape(str(normalization.get("permissions", 0)))
    events = html.escape(str(normalization.get("access_events", 0)))
    processes = html.escape(str(normalization.get("processes", 0)))

    st.markdown(
        f"""
        <div class="pipeline-panel">
            <div class="panel-title">
                <h3>Evidence Normalization</h3>
                <span>{source_stack}</span>
            </div>
            <div class="pipeline">
                <div class="pipeline-step">
                    <strong>Raw packet</strong>
                    <span>{raw_format}</span>
                </div>
                <div class="pipeline-step">
                    <strong>Normalized model</strong>
                    <span>{users} users, {groups} groups, {devices} devices, {processes} processes, {permissions} permissions, {events} access events.</span>
                </div>
                <div class="pipeline-step">
                    <strong>Deterministic check</strong>
                    <span>Assessment objectives are evaluated from evidence references before AI remediation is generated.</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_time_to_finding_comparison(result: dict[str, Any]) -> None:
    runtime = result.get("context", {}).get("runtime_metrics", {})
    elapsed = html.escape(str(runtime.get("verification_elapsed_ms", 0)))
    findings = html.escape(str(runtime.get("findings_found", len(result.get("findings", [])))))
    evidence_count = html.escape(str(len(result.get("evidence_refs", []))))

    st.markdown(
        f"""
        <div class="comparison-panel">
            <div class="panel-title">
                <h3>Validation Snapshot</h3>
                <span>Representative packet, not production customer data</span>
            </div>
            <div class="comparison-grid">
                <div class="comparison-cell">
                    <strong>{evidence_count}</strong>
                    <span>Evidence files normalized automatically.</span>
                </div>
                <div class="comparison-cell">
                    <strong>{elapsed} ms</strong>
                    <span>Measured deterministic verification time for this packet.</span>
                </div>
                <div class="comparison-cell">
                    <strong>{findings}</strong>
                    <span>Evidence-linked findings returned from seeded or clean state.</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _safe_preview_file(path: Path) -> None:
    st.markdown(f"**{path.name}**")
    try:
        if path.suffix == ".csv":
            rows = _read_csv_rows(path)
            st.dataframe(rows, use_container_width=True)
            return
        if path.suffix == ".json":
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            st.json(payload, expanded=False)
            return
        if path.suffix == ".md":
            text = path.read_text(encoding="utf-8")
            st.code(text[:4000], language="markdown")
            return
        st.caption("Preview not available for this file type.")
    except Exception as exc:  # demo-friendly display
        st.error(f"Could not read `{path.name}`: {exc}")


def _runtime_packet_dir() -> Path:
    return Path.cwd() / ".ncat_runtime" / "active_packet"


def _start_ncat(source_dir: Path) -> Path:
    runtime_dir = _runtime_packet_dir()
    if runtime_dir.exists():
        shutil.rmtree(runtime_dir)
    shutil.copytree(source_dir, runtime_dir)
    st.session_state.ncat_running = True
    st.session_state.ncat_packet_dir = str(runtime_dir.resolve())
    st.session_state.ncat_source_dir = str(source_dir.resolve())
    st.session_state.ncat_event_log = [
        "NCAT monitor started from representative evidence packet."
    ]
    return runtime_dir


def _reset_ncat() -> Path:
    source_dir = Path(st.session_state.ncat_source_dir)
    runtime_dir = _start_ncat(source_dir)
    st.session_state.ncat_event_log = ["NCAT runtime evidence reset to clean baseline."]
    return runtime_dir


def _stop_ncat() -> None:
    st.session_state.ncat_running = False
    st.session_state.ncat_event_log.append("NCAT monitor stopped.")


def _clear_llm_cache(packet_dir: str | Path | None = None) -> None:
    st.session_state.llm_attempted_signatures = set()
    if packet_dir:
        remediation_path = Path(packet_dir) / "outputs" / "remediation_steps.md"
        if remediation_path.exists():
            remediation_path.unlink()


def _is_okta_box_jamf_packet(packet_dir: Path) -> bool:
    return (packet_dir / "box_collaborations.json").exists()


def _append_csv_row_once(path: Path, row: list[str]) -> bool:
    existing = path.read_text(encoding="utf-8").splitlines()
    row_text = ",".join(row)
    if row_text in existing:
        return False
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write("\n" + row_text)
    return True


def _remove_csv_rows(path: Path, predicate: Any) -> int:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fieldnames = reader.fieldnames or []
    kept = [row for row in rows if not predicate(row)]
    removed = len(rows) - len(kept)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(kept)
    return removed


def _append_csv_dict_row_once(path: Path, row: dict[str, str]) -> bool:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fieldnames = reader.fieldnames or list(row)
    if any(all(existing.get(key) == value for key, value in row.items()) for existing in rows):
        return False
    rows.append(row)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return True


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _microsoft_group_id(packet_dir: Path, group_name: str) -> str:
    for row in _read_csv_rows(packet_dir / "entra_groups.csv"):
        if row.get("group_name") == group_name:
            return row.get("group_id", "")
    return ""


def _microsoft_guest_user_id(packet_dir: Path) -> str:
    for row in _read_csv_rows(packet_dir / "entra_users.csv"):
        if row.get("user_type") == "Guest":
            return row.get("user_id", "")
    return ""


def _okta_authorized_group(payload: dict[str, Any]) -> dict[str, Any] | None:
    for group in payload.get("groups", []):
        if group.get("profile", {}).get("name") == "CUI-Authorized":
            return group
    return None


def _okta_guest_user(packet_dir: Path) -> dict[str, Any] | None:
    users = _load_json(packet_dir / "okta_users.json")
    for user in users.get("items", []):
        if user.get("type", {}).get("name") == "Guest":
            return user
    return None


def _inject_unauthorized_user(packet_dir: Path) -> str:
    if _is_okta_box_jamf_packet(packet_dir):
        path = packet_dir / "okta_groups.json"
        payload = _load_json(path)
        group = _okta_authorized_group(payload)
        guest = _okta_guest_user(packet_dir)
        if not group or not guest:
            return "Could not inject Okta user drift because the authorized group or guest user was missing."
        embedded = group.setdefault("_embedded", {}).setdefault("users", [])
        if any(user.get("id") == guest.get("id") for user in embedded):
            return "Unauthorized Okta guest group membership was already present."
        embedded.append(
            {
                "id": guest.get("id", ""),
                "profile": {
                    "login": guest.get("profile", {}).get("login", ""),
                },
                "ncat_injected": True,
            }
        )
        _write_json(path, payload)
        return "Injected group-membership drift: external Okta guest added to CUI-Authorized."

    group_id = _microsoft_group_id(packet_dir, "CUI-Authorized")
    guest_id = _microsoft_guest_user_id(packet_dir)
    if not group_id or not guest_id:
        return "Could not inject Microsoft user drift because the authorized group or guest user was missing."
    changed = _append_csv_dict_row_once(
        packet_dir / "entra_group_members.csv",
        {"group_id": group_id, "user_id": guest_id},
    )
    if not changed:
        return "Unauthorized Microsoft guest group membership was already present."
    return "Injected group-membership drift: external Entra guest added to CUI-Authorized."


def _inject_unauthorized_device(packet_dir: Path) -> str:
    if _is_okta_box_jamf_packet(packet_dir):
        path = packet_dir / "access_events.json"
        payload = _load_json(path)
        if any(event.get("uuid") == "evt_bad_device" for event in payload["events"]):
            return "Unauthorized Jamf device event was already present."
        payload["events"].append(
            {
                "uuid": "evt_bad_device",
                "published": "2026-03-03T16:00:00.000Z",
                "eventType": "box.folder.download",
                "actor": {
                    "type": "User",
                    "id": "00u1alice",
                    "displayName": "Alice Johnson",
                },
                "target": {
                    "type": "box.folder",
                    "id": "box_folder_7788",
                    "displayName": "CUI-Contracts-Box-Folder",
                },
                "client": {
                    "ipAddress": "203.0.113.99",
                    "userAgent": "Box Web",
                    "device": {"source": "jamf", "id": "jamf-199"},
                },
            }
        )
        _write_json(path, payload)
        return "Injected CUI access event from unmanaged/non-compliant Jamf device."

    removed = _remove_csv_rows(
        packet_dir / "authorized_devices.csv",
        lambda row: row.get("site_name") == "Contracts-CUI"
        and row.get("device_id") == "dev-001",
    )
    if not removed:
        return "Device allowlist mismatch was already present."
    return "Injected device allowlist drift by removing dev-001 from approved CUI devices."


def _repair_unauthorized_user(packet_dir: Path) -> str:
    if _is_okta_box_jamf_packet(packet_dir):
        path = packet_dir / "okta_groups.json"
        payload = _load_json(path)
        group = _okta_authorized_group(payload)
        if not group:
            return "Could not repair Okta user drift because CUI-Authorized was missing."
        embedded = group.setdefault("_embedded", {}).setdefault("users", [])
        before = len(embedded)
        group["_embedded"]["users"] = [
            user for user in embedded if user.get("id") != "00u9guest"
        ]
        _write_json(path, payload)
        removed = before - len(group["_embedded"]["users"])
        if removed:
            return "Approved remediation applied: removed external Okta guest from CUI-Authorized."
        return "No injected Okta guest group membership was present to remove."

    group_id = _microsoft_group_id(packet_dir, "CUI-Authorized")
    guest_id = _microsoft_guest_user_id(packet_dir)
    removed = _remove_csv_rows(
        packet_dir / "entra_group_members.csv",
        lambda row: row.get("group_id") == group_id and row.get("user_id") == guest_id,
    )
    if removed:
        return "Approved remediation applied: removed external Entra guest from CUI-Authorized."
    return "No injected Microsoft guest group membership was present to remove."


def _repair_unauthorized_device(packet_dir: Path) -> str:
    if _is_okta_box_jamf_packet(packet_dir):
        path = packet_dir / "access_events.json"
        payload = _load_json(path)
        before = len(payload.get("events", []))
        payload["events"] = [
            event for event in payload.get("events", []) if event.get("uuid") != "evt_bad_device"
        ]
        _write_json(path, payload)
        removed = before - len(payload["events"])
        if removed:
            return "Approved remediation applied: removed injected unmanaged Jamf device event."
        return "No injected Jamf device event was present to remove."

    changed = _append_csv_dict_row_once(
        packet_dir / "authorized_devices.csv",
        {"site_name": "Contracts-CUI", "device_id": "dev-001"},
    )
    if changed:
        return "Approved remediation applied: restored dev-001 to approved CUI devices."
    return "dev-001 was already present in approved CUI devices."


def _approve_action(packet_dir: Path, finding: str) -> str:
    if "Guest/external user" in finding or "Unauthorized user" in finding:
        return _repair_unauthorized_user(packet_dir)
    if "device" in finding.lower():
        return _repair_unauthorized_device(packet_dir)
    return "Approval recorded, but this finding type does not have an automated packet fix yet."


def _rerun() -> None:
    rerun = getattr(st, "rerun", None) or getattr(st, "experimental_rerun")
    rerun()


def _finding_signature(result: dict[str, Any]) -> str:
    payload = {
        "control_id": result.get("control_id"),
        "status": result.get("status"),
        "findings": result.get("findings", []),
        "proposed_actions": result.get("proposed_actions", []),
        "source_stack": result.get("context", {}).get("source_stack"),
    }
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _render_llm_once(packet_dir: str | Path, result: dict[str, Any]) -> None:
    if result["status"] != "NOT MET":
        return

    st.markdown("### LLM Remediation")
    signature = _finding_signature(result)
    remediation_path = Path(packet_dir) / "outputs" / "remediation_steps.md"

    if signature in st.session_state.llm_attempted_signatures:
        if remediation_path.exists():
            st.caption("LLM remediation already generated for this exact finding state.")
            st.markdown(remediation_path.read_text(encoding="utf-8"))
        else:
            st.info("LLM remediation was already attempted for this finding state.")
        return

    st.session_state.llm_attempted_signatures.add(signature)
    try:
        with st.spinner("waiting for llm remediation_steps"):
            remediation_path = generate_remediation_markdown(packet_dir)
        st.success("LLM remediation generated once for this finding state.")
        remediation_text = remediation_path.read_text(encoding="utf-8")
        st.markdown(remediation_text)
        with remediation_path.open("rb") as handle:
            st.download_button(
                "Download remediation_steps.md",
                data=handle.read(),
                file_name="remediation_steps.md",
                mime="text/markdown",
            )
    except Exception as exc:
        st.error(f"Could not generate LLM remediation: {exc}")


def _render_verification_result(packet_dir: str | Path, heading: str) -> None:
    st.markdown(f"## {heading}")
    try:
        result = verify_packet(packet_dir)
        scorecard_path, report_path = write_outputs(packet_dir, result)

        status = result["status"]
        findings = result.get("findings", [])
        context = result.get("context", {})
        severity_counts = Counter(_dashboard_severity(f) for f in findings)
        total_findings = len(findings)
        status_text = html.escape(_status_label(status))
        source_stack = html.escape(str(context.get("source_stack", "Unknown")))
        resource_name = html.escape(str(context.get("resource_name", "Unknown")))
        status_class = _status_class(status)

        st.markdown(
            f"""
            <div class="status-strip">
                <div>
                    <h3>{html.escape(result["control_id"])} assessment result</h3>
                    <p>{source_stack} evidence evaluated for <strong>{resource_name}</strong>.</p>
                </div>
                <div class="pill {status_class}">{status_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        _render_summary_cards(result)

        readiness_cols = st.columns([1.35, 0.85])
        with readiness_cols[0]:
            _render_objective_readiness(result)
        with readiness_cols[1]:
            _render_action_queue(result)

        if findings:
            st.markdown(
                '<span id="findings-jump-target"></span>',
                unsafe_allow_html=True,
            )
            st.markdown("### Evidence-Linked Findings")
            st.dataframe(
                _findings_for_display(findings),
                use_container_width=True,
                hide_index=True,
            )

        overview_tab, findings_tab, remediation_tab, evidence_tab = st.tabs(
            ["Overview", "Findings", "Remediation", "Evidence & exports"]
        )

        with overview_tab:
            _render_evidence_pipeline(result)
            st.write("")
            _render_time_to_finding_comparison(result)
            st.write("")

            st.markdown("### Time-to-Finding")
            runtime = context.get("runtime_metrics", {})
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Elapsed", f"{runtime.get('verification_elapsed_ms', 0)} ms")
            c2.metric("Users", runtime.get("users_evaluated", 0))
            c3.metric("Devices", runtime.get("devices_evaluated", 0))
            c4.metric("Permission Edges", runtime.get("permission_edges_evaluated", 0))
            c5.metric("Findings", runtime.get("findings_found", total_findings))

            st.markdown("### Assessment Objectives")
            objectives = context.get("assessment_objectives")
            if objectives:
                objective_rows = [
                    {
                        "objective": k.replace("_", " "),
                        "status": v,
                    }
                    for k, v in objectives.items()
                ]
                st.dataframe(
                    objective_rows,
                    use_container_width=True,
                    hide_index=True,
                )

            st.markdown("### Normalized Evidence Model")
            normalization = context.get("normalization_summary", {})
            st.dataframe(
                [
                    {"field": str(key), "value": str(value)}
                    for key, value in normalization.items()
                ],
                use_container_width=True,
                hide_index=True,
            )

        with findings_tab:
            st.markdown("### Finding Summary")
            e1, e2, e3, e4, e5 = st.columns(5)
            e1.metric("Total", total_findings)
            e2.metric("High", severity_counts.get("high", 0))
            e3.metric("Medium", severity_counts.get("medium", 0))
            e4.metric("Low", severity_counts.get("low", 0))
            e5.metric("Info", severity_counts.get("info", 0))

            if findings:
                st.markdown("### Root Causes")
                bucket_counts = Counter(_root_cause_bucket(f) for f in findings)
                st.dataframe(
                    [
                        {"category": category, "count": count}
                        for category, count in sorted(
                            bucket_counts.items(), key=lambda x: x[1], reverse=True
                        )
                    ],
                    use_container_width=True,
                    hide_index=True,
                )

                st.markdown("### Evidence-Linked Findings")
                st.dataframe(
                    _findings_for_display(findings),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No findings. Effective access complies with the configured CUI access rules.")

        with remediation_tab:
            proposed_actions = result.get("proposed_actions", [])
            if proposed_actions:
                st.markdown("### Human-Approved Candidate Actions")
                finding_signature = _finding_signature(result)
                for idx, action in enumerate(proposed_actions, start=1):
                    finding_text = action.get("finding", "")
                    st.markdown(
                        f"""
                        <div class="action-card">
                            <div class="mini-label">Pending approval</div>
                            <strong>{html.escape(action.get("proposed_action", ""))}</strong>
                            <span><strong>Operator action:</strong> {html.escape(action.get("operator_action", ""))}</span><br>
                            <span><strong>Candidate API:</strong> {html.escape(action.get("api_label", "Technical action"))} - <code>{html.escape(action.get("candidate_api_call", ""))}</code></span><br>
                            <span><strong>Risk:</strong> {html.escape(action.get("risk", ""))}</span><br>
                            <span><strong>Required approval:</strong> {html.escape(action.get("required_approval", ""))}</span><br>
                            <span><strong>Finding:</strong> {html.escape(finding_text)}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    cols = st.columns([1, 1, 1, 5])
                    if cols[0].button("Approve", key=f"approve_{idx}_{finding_signature}"):
                        st.session_state.ncat_event_log.append(
                            _approve_action(Path(packet_dir), finding_text)
                        )
                        _clear_llm_cache(packet_dir)
                        _rerun()
                    if cols[1].button("Reject", key=f"reject_{idx}_{finding_signature}"):
                        st.session_state.ncat_event_log.append(
                            f"Rejected remediation; evidence left unchanged for finding: {finding_text}"
                        )
                        _rerun()
                    if cols[2].button("Ticket", key=f"ticket_{idx}_{finding_signature}"):
                        st.session_state.ncat_event_log.append(
                            f"Created ticket; evidence left unchanged for finding: {finding_text}"
                        )
                        _rerun()
                    cols[3].caption("Actions update only the runtime packet during the demo.")
            elif status == "MET":
                st.success("No remediation required for the current evidence state.")
            else:
                st.info("No automated candidate action is available for this finding type.")

            _render_llm_once(packet_dir, result)

        with evidence_tab:
            st.markdown("### Evidence Used")
            st.dataframe(
                [{"evidence file": evidence} for evidence in result["evidence_refs"]],
                use_container_width=True,
                hide_index=True,
            )

            st.markdown("### Output Files")
            st.caption(f"scorecard.json: `{scorecard_path}`")
            st.caption(f"report.md: `{report_path}`")
            d1, d2 = st.columns(2)
            with scorecard_path.open("rb") as handle:
                d1.download_button(
                    "Download scorecard.json",
                    data=handle.read(),
                    file_name="scorecard.json",
                    mime="application/json",
                )
            with report_path.open("rb") as handle:
                d2.download_button(
                    "Download report.md",
                    data=handle.read(),
                    file_name="report.md",
                    mime="text/markdown",
                )
    except Exception as exc:
        st.error(f"Verification failed: {exc}")


_init_session_state()
_inject_global_styles()

st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">NexGen Compliance Automation</div>
        <h1>CMMC Level 2 continuous verification for CUI access.</h1>
        <p>
            Demonstrates AC.L2-3.1.1 across multiple enterprise stacks with deterministic
            evidence checks, measurable time-to-finding, and human-approved remediation.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)
_render_proof_cards()

packet_options = {
    "Microsoft: Entra + SharePoint + Intune": Path.cwd() / "packet_ac_l2_3_1_1_microsoft",
    "Okta + Box + Jamf": Path.cwd() / "packet_ac_l2_3_1_1_okta_box_jamf",
    "Legacy Level 1 packet": Path.cwd() / "packet_ac_l1_b_1_i",
}

with st.sidebar:
    st.title("NexGen")
    st.caption("Continuous verifier demo")
    st.divider()
    selected_packet_label = st.selectbox(
        "Evidence stack",
        options=list(packet_options),
        index=0,
    )
    default_packet = str(packet_options[selected_packet_label].resolve())
    packet_dir = st.text_input("Packet folder", value=default_packet)
    show_preview = st.checkbox("Show raw evidence", value=False)
    show_roadmap = st.checkbox("Show Level 2 roadmap", value=True)
    run_ncat = st.button("Run NCAT", type="primary", use_container_width=True)
    st.divider()
    st.markdown("**Demo sequence**")
    st.caption("1. Run NCAT on the clean packet.")
    st.caption("2. Inject user or device drift.")
    st.caption("3. Review findings and candidate API actions.")
    st.caption("4. Approve, reject, or ticket the change.")

source_packet_path = Path(packet_dir)

if run_ncat:
    if source_packet_path.exists():
        packet_dir = str(_start_ncat(source_packet_path))
    else:
        st.error(f"Packet folder does not exist: `{source_packet_path}`")

if st.session_state.ncat_running and st.session_state.ncat_packet_dir:
    packet_dir = st.session_state.ncat_packet_dir

packet_path = Path(packet_dir)

if st.session_state.ncat_running:
    st.markdown(
        f"""
        <div class="monitor-bar">
            <strong>NCAT monitor is live</strong><br>
            <span>Runtime packet: {html.escape(str(packet_path))}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    status_cols = st.columns([1, 1, 1, 1])
    if status_cols[0].button("Inject User", use_container_width=True):
        st.session_state.ncat_event_log.append(_inject_unauthorized_user(packet_path))
        _clear_llm_cache(packet_path)
    if status_cols[1].button("Inject Device", use_container_width=True):
        st.session_state.ncat_event_log.append(_inject_unauthorized_device(packet_path))
        _clear_llm_cache(packet_path)
    if status_cols[2].button("Reset", use_container_width=True):
        packet_path = _reset_ncat()
        packet_dir = str(packet_path)
        _clear_llm_cache(packet_path)
    if status_cols[3].button("Stop", use_container_width=True):
        _stop_ncat()

    with st.expander("NCAT event log", expanded=True):
        for event in st.session_state.ncat_event_log[-6:]:
            st.write(f"- {event}")
else:
    st.markdown("### Ready to verify")
    st.info("Choose a representative evidence stack in the sidebar and run NCAT to create a clean runtime packet.")

st.markdown("### Representative Evidence Stack")
stack_rows = [
    {
        "stack": "Microsoft",
        "identity": "Entra ID",
        "resource permissions": "SharePoint",
        "device posture": "Intune",
        "raw shape": "CSV exports",
    },
    {
        "stack": "Non-Microsoft",
        "identity": "Okta",
        "resource permissions": "Box",
        "device posture": "Jamf",
        "raw shape": "Nested API-style JSON",
    },
]
st.dataframe(stack_rows, use_container_width=True, hide_index=True)

if show_preview:
    st.markdown("### Raw Evidence Preview")
    if not packet_path.exists():
        st.error(f"Packet folder does not exist: `{packet_path}`")
    else:
        st.caption(
            "The two source stacks intentionally use different raw shapes. Microsoft is flat CSV; "
            "Okta/Box/Jamf is nested API-style JSON."
        )
        for path in sorted(packet_path.iterdir()):
            if path.is_file() and path.suffix in {".csv", ".json", ".md"}:
                with st.expander(path.name, expanded=path.name == "control_doc.md"):
                    _safe_preview_file(path)

if show_roadmap:
    st.markdown("### CMMC Level 2 Coverage Roadmap")
    st.dataframe(
        [
            {
                "area": "Access Control",
                "requirement": "AC.L2-3.1.1",
                "status": "Implemented in this demo",
                "evidence pattern": "identity, groups, permissions, devices, processes, access events",
            },
            {
                "area": "Access Control",
                "requirement": "Related AC objectives",
                "status": "Adapter-ready roadmap",
                "evidence pattern": "same normalized entities plus requirement-specific tests",
            },
            {
                "area": "Other Level 2 families",
                "requirement": "Awareness, Audit, Configuration, IA, IR, SI, etc.",
                "status": "Roadmap only",
                "evidence pattern": "new objective mappers and deterministic checks",
            },
        ],
        use_container_width=True,
        hide_index=True,
    )

if st.session_state.ncat_running:
    _render_verification_result(packet_dir, "Readiness Overview")
