"""Streamlit demo app for AC.L2-3.1.1 evidence verification."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import streamlit as st

from ac_l1_b_1_i_verifier import _read_csv_rows, verify_packet, write_outputs
from generate_remediation_with_openai import generate_remediation_markdown


st.set_page_config(
    page_title="NexGen CMMC Level 2 Verifier - AC.L2-3.1.1",
    page_icon="AC",
    layout="wide",
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
    st.subheader(heading)
    try:
        result = verify_packet(packet_dir)
        scorecard_path, report_path = write_outputs(packet_dir, result)

        status = result["status"]
        if status == "MET":
            st.success("Status: MET")
        elif status == "NOT MET":
            st.error("Status: NOT MET")
        else:
            st.warning("Status: NOT APPLICABLE")

        findings = result.get("findings", [])
        context = result.get("context", {})
        severity_counts = Counter(_dashboard_severity(f) for f in findings)
        total_findings = len(findings)

        st.markdown("### Time-to-Finding Metrics")
        runtime = context.get("runtime_metrics", {})
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Elapsed ms", runtime.get("verification_elapsed_ms", 0))
        c2.metric("Users", runtime.get("users_evaluated", 0))
        c3.metric("Devices", runtime.get("devices_evaluated", 0))
        c4.metric("Permission Edges", runtime.get("permission_edges_evaluated", 0))
        c5.metric("Findings", runtime.get("findings_found", total_findings))

        st.markdown("### Normalization")
        normalization = context.get("normalization_summary", {})
        st.dataframe(
            [{"field": key, "value": value} for key, value in normalization.items()],
            use_container_width=True,
            hide_index=True,
        )

        st.json(
            {
                "control_id": result["control_id"],
                "source_stack": context.get("source_stack"),
                "resource_name": context.get("resource_name"),
                "status": result["status"],
                "findings_count": total_findings,
                "effective_access_count": context.get("effective_access_count"),
            }
        )

        st.markdown("### Error Dashboard")
        e1, e2, e3, e4, e5 = st.columns(5)
        e1.metric("Total Errors", total_findings)
        e2.metric("High", severity_counts.get("high", 0))
        e3.metric("Medium", severity_counts.get("medium", 0))
        e4.metric("Low", severity_counts.get("low", 0))
        e5.metric("Info", severity_counts.get("info", 0))

        if findings:
            st.markdown("#### Error Categories")
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

        objectives = context.get("assessment_objectives")
        if objectives:
            st.markdown("### Assessment Objectives")
            st.dataframe(
                [{"objective": k, "status": v} for k, v in objectives.items()],
                use_container_width=True,
                hide_index=True,
            )

        st.markdown("### Findings")
        if findings:
            findings_for_display = []
            for finding in findings:
                normalized_severity = _dashboard_severity(finding)
                findings_for_display.append(
                    {
                        "severity": _severity_badge(normalized_severity),
                        "root_cause": _root_cause_bucket(finding),
                        "message": finding.get("message", ""),
                        "evidence_ref": finding.get("evidence_ref", ""),
                    }
                )
            st.dataframe(findings_for_display, use_container_width=True, hide_index=True)
        else:
            st.info("No findings. Effective access complies with configured rules.")

        proposed_actions = result.get("proposed_actions", [])
        if proposed_actions:
            st.markdown("### Human-Approved Remediation Actions")
            actions_for_display = []
            finding_signature = _finding_signature(result)
            for idx, action in enumerate(proposed_actions, start=1):
                finding_text = action.get("finding", "")
                actions_for_display.append(
                    {
                        "approval_state": "Pending approval",
                        "action": action.get("proposed_action", ""),
                        "candidate_api_call": action.get("candidate_api_call", ""),
                        "required_approval": action.get("required_approval", ""),
                        "risk": action.get("risk", ""),
                    }
                )
                cols = st.columns([1, 1, 1, 4])
                if cols[0].button("Approve", key=f"approve_{idx}_{finding_signature}"):
                    st.session_state.ncat_event_log.append(
                        _approve_action(Path(packet_dir), finding_text)
                    )
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
                cols[3].caption(finding_text)
            st.dataframe(actions_for_display, use_container_width=True, hide_index=True)

        st.markdown("### Evidence Used")
        for evidence in result["evidence_refs"]:
            st.write(f"- `{evidence}`")

        st.markdown("### Output Files")
        st.write(f"- `scorecard.json`: `{scorecard_path}`")
        st.write(f"- `report.md`: `{report_path}`")

        with scorecard_path.open("rb") as handle:
            st.download_button(
                "Download scorecard.json",
                data=handle.read(),
                file_name="scorecard.json",
                mime="application/json",
            )
        with report_path.open("rb") as handle:
            st.download_button(
                "Download report.md",
                data=handle.read(),
                file_name="report.md",
                mime="text/markdown",
            )

        _render_llm_once(packet_dir, result)
    except Exception as exc:
        st.error(f"Verification failed: {exc}")


_init_session_state()

st.title("NexGen CMMC Level 2 Continuous Verifier")
st.markdown(
    """
This demo verifies CMMC Level 2 `AC.L2-3.1.1` using deterministic, explainable checks.
It evaluates whether only authorized users, processes, and devices can access a CUI resource.
"""
)

st.subheader("Demo Scope")
st.markdown(
    """
- Working control: `AC.L2-3.1.1` Authorized Access Control.
- Evidence sources: Microsoft Entra/SharePoint/Intune or Okta/Box/Jamf.
- Architecture: raw stack exports normalize into one evidence model, then the same verifier runs.
- AI role: explain deterministic findings and propose human-approved remediation actions.
"""
)

packet_options = {
    "Microsoft CSV packet": Path.cwd() / "packet_ac_l2_3_1_1_microsoft",
    "Okta/Box/Jamf JSON packet": Path.cwd() / "packet_ac_l2_3_1_1_okta_box_jamf",
    "Original L1 packet": Path.cwd() / "packet_ac_l1_b_1_i",
}

st.subheader("Evidence Packet")
selected_packet_label = st.selectbox(
    "Choose representative evidence packet",
    options=list(packet_options),
    index=0,
)
default_packet = str(packet_options[selected_packet_label].resolve())
packet_dir = st.text_input("Evidence packet folder", value=default_packet)
source_packet_path = Path(packet_dir)

left, middle, right = st.columns([1, 1, 1])
with left:
    show_preview = st.checkbox("Preview raw evidence", value=True)
with middle:
    show_roadmap = st.checkbox("Show Level 2 roadmap", value=True)
with right:
    run_ncat = st.button("Run NCAT", type="primary")

if run_ncat:
    if source_packet_path.exists():
        packet_dir = str(_start_ncat(source_packet_path))
    else:
        st.error(f"Packet folder does not exist: `{source_packet_path}`")

if st.session_state.ncat_running and st.session_state.ncat_packet_dir:
    packet_dir = st.session_state.ncat_packet_dir

packet_path = Path(packet_dir)

if st.session_state.ncat_running:
    st.subheader("NCAT Continuous Monitor")
    st.caption(
        "NCAT is watching the active runtime packet. Each inject mutates the runtime evidence "
        "and triggers one Streamlit rerun; the LLM remediation call is gated to one attempt per unique finding state."
    )
    status_cols = st.columns([2, 1, 1, 1])
    status_cols[0].info(f"Active runtime evidence: `{packet_path}`")
    if status_cols[1].button("Inject User"):
        st.session_state.ncat_event_log.append(_inject_unauthorized_user(packet_path))
    if status_cols[2].button("Inject Device"):
        st.session_state.ncat_event_log.append(_inject_unauthorized_device(packet_path))
    if status_cols[3].button("Reset"):
        packet_path = _reset_ncat()
        packet_dir = str(packet_path)

    if st.button("Stop NCAT"):
        _stop_ncat()

    st.markdown("#### NCAT Event Log")
    for event in st.session_state.ncat_event_log[-6:]:
        st.write(f"- {event}")

if show_preview:
    st.subheader("Raw Evidence Preview")
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
    st.subheader("CMMC Level 2 Coverage Roadmap")
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
    _render_verification_result(packet_dir, "NCAT Monitor Result")
