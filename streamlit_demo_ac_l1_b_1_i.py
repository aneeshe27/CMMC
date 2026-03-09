"""Streamlit demo app for AC.L1-B.1.I evidence verification."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from ac_l1_b_1_i_verifier import _read_csv_rows, verify_packet, write_outputs
from generate_remediation_with_openai import generate_remediation_markdown


st.set_page_config(
    page_title="CMMC L1 Demo Agent - AC.L1-B.1.I",
    page_icon="🔐",
    layout="wide",
)

st.title("CMMC L1 Demo Agent: AC.L1-B.1.I (Authorized Access Control)")
st.markdown(
    """
This demo verifies one CMMC Level 1 control using deterministic, explainable checks.
It evaluates whether only authorized users, processes, and devices have effective access to an FCI SharePoint site.

**Control in scope**
- `AC.L1-B.1.I` Authorized Access Control
- Requirement: Limit system access to authorized users, processes, and devices.
- Demo scope: deterministic checks for authorized users, authorized processes, and authorized devices.
"""
)

st.subheader("How This Demo Works")
st.markdown(
    """
1. You provide a local **evidence packet folder**.
2. The verifier reads the control config and CSV exports.
3. It expands SharePoint group permissions to individual users.
4. It checks effective users plus process/device access events against policy rules.
5. It returns `MET`, `NOT MET`, or `NOT APPLICABLE` with concrete evidence references.
6. If device/process evidence files are present, it also checks authorized processes and Intune-managed devices.
"""
)

st.subheader("Evidence Packet Files (Natural Language Explanation)")
st.markdown(
    """
- `control_doc.md`  
  Human-readable policy and scope for the control, including:
  FCI site name, authorized group name, and rules (for example, no guest users).

- `entra_users.csv`  
  Entra user inventory used to evaluate each user identity:
  `user_id`, username/email, enabled/disabled status, and whether the user is `Member` or `Guest`.

- `entra_groups.csv`  
  Group catalog that maps `group_id` to `group_name`.
  This is where the verifier finds the authorized group (for example, `FCI-Authorized`).

- `entra_group_members.csv`  
  Group membership mapping (`group_id` -> `user_id`).
  This allows the verifier to determine whether a user is in the authorized group.

- `sharepoint_site_permissions.csv`  
  Simplified export of who has access to a SharePoint site.
  Access can be granted to users directly or to groups.
  If granted to groups, the verifier expands group members and treats them as effective access.

- `intune_devices.csv` + `authorized_devices.csv`  
  Simulated Intune posture and approved device list for the FCI site.
  Devices must be managed, compliant, and approved to pass device checks.

- `entra_service_principals.csv` + `authorized_processes.csv`  
  Process/app identities and allowed process list for the FCI site.
  Apps must be enabled and explicitly authorized.

- `fci_access_events.csv`  
  Simplified access events that connect users/apps to devices.
  This allows objective checks for process- and device-based access controls.
"""
)

default_packet = str((Path.cwd() / "packet_ac_l1_b_1_i").resolve())
packet_dir = st.text_input("Evidence packet folder", value=default_packet)

left, right = st.columns([1, 1])
with left:
    show_preview = st.checkbox("Preview evidence tables", value=True)
with right:
    run_verification = st.button("Verify AC.L1-B.1.I", type="primary")


def _safe_preview_csv(label: str, path: Path) -> None:
    st.markdown(f"**{label}**")
    try:
        rows = _read_csv_rows(path)
        if rows:
            st.dataframe(rows, use_container_width=True)
        else:
            st.info("File is present but contains no data rows.")
    except Exception as exc:  # demo-friendly display
        st.error(f"Could not read `{path.name}`: {exc}")


if show_preview:
    st.subheader("Evidence Preview")
    packet_path = Path(packet_dir)
    _safe_preview_csv("Entra Users", packet_path / "entra_users.csv")
    _safe_preview_csv("Entra Groups", packet_path / "entra_groups.csv")
    _safe_preview_csv("Entra Group Members", packet_path / "entra_group_members.csv")
    _safe_preview_csv(
        "SharePoint Site Permissions", packet_path / "sharepoint_site_permissions.csv"
    )
    _safe_preview_csv("Intune Devices", packet_path / "intune_devices.csv")
    _safe_preview_csv("Authorized Devices", packet_path / "authorized_devices.csv")
    _safe_preview_csv(
        "Entra Service Principals", packet_path / "entra_service_principals.csv"
    )
    _safe_preview_csv("Authorized Processes", packet_path / "authorized_processes.csv")
    _safe_preview_csv("FCI Access Events", packet_path / "fci_access_events.csv")

if run_verification:
    st.subheader("Verification Result")
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

        st.json(
            {
                "control_id": result["control_id"],
                "status": result["status"],
                "findings_count": len(result["findings"]),
                "effective_access_count": result["context"]["effective_access_count"],
            }
        )

        objectives = result["context"].get("assessment_objectives")
        if objectives:
            st.markdown("### Assessment Objectives")
            st.dataframe(
                [
                    {"objective": k, "status": v}
                    for k, v in objectives.items()
                ],
                use_container_width=True,
            )

        st.markdown("### Findings")
        if result["findings"]:
            st.dataframe(result["findings"], use_container_width=True)
        else:
            st.info("No findings. Effective access complies with configured rules.")

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

        if status == "NOT MET":
            st.markdown("### LLM Remediation")
            try:
                with st.spinner("waiting for llm remediation_steps"):
                    remediation_path = generate_remediation_markdown(packet_dir)
                st.success("LLM remediation generated.")
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
    except Exception as exc:
        st.error(f"Verification failed: {exc}")

