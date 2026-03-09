"""Deterministic verifier for CMMC AC.L1-B.1.I demo evidence packets."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class EffectiveAccess:
    user_id: str
    source_row: int
    source_principal_type: str
    source_principal_id: str
    role: str


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing evidence file: {path}")

    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row_num, row in enumerate(reader, start=2):  # header is line 1
            normalized = {k.strip(): (v or "").strip() for k, v in row.items()}
            normalized["_row"] = str(row_num)
            rows.append(normalized)
    return rows


def _read_optional_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    return _read_csv_rows(path)


def _is_true(value: str) -> bool:
    return value.strip().lower() == "true"


def _parse_control_doc(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing evidence file: {path}")

    parsed: dict[str, Any] = {"rules_text": []}
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if line.startswith("- ") and ":" in line:
                key, value = line[2:].split(":", 1)
                parsed[key.strip()] = value.strip()
            if line[:2].isdigit() and ". " in line:
                parsed["rules_text"].append(line)

    rules_blob = " ".join(parsed["rules_text"]).lower()
    parsed["block_guest_users"] = ("guest not allowed" in rules_blob) or (
        "external identities are prohibited" in rules_blob
    )
    return parsed


def _build_group_membership(group_rows: list[dict[str, str]]) -> dict[str, set[str]]:
    members_by_group: dict[str, set[str]] = defaultdict(set)
    for row in group_rows:
        group_id = row.get("group_id", "")
        user_id = row.get("user_id", "")
        if group_id and user_id:
            members_by_group[group_id].add(user_id)
    return members_by_group


def _resolve_authorized_group_id(
    groups: list[dict[str, str]], authorized_group_name: str
) -> str | None:
    for row in groups:
        if row.get("group_name") == authorized_group_name:
            return row.get("group_id")
    return None


def verify_packet(packet_dir: str | Path) -> dict[str, Any]:
    packet_path = Path(packet_dir).resolve()
    control = _parse_control_doc(packet_path / "control_doc.md")
    users = _read_csv_rows(packet_path / "entra_users.csv")
    groups = _read_csv_rows(packet_path / "entra_groups.csv")
    group_members = _read_csv_rows(packet_path / "entra_group_members.csv")
    sp_permissions = _read_csv_rows(packet_path / "sharepoint_site_permissions.csv")
    intune_devices = _read_optional_csv_rows(packet_path / "intune_devices.csv")
    authorized_devices = _read_optional_csv_rows(packet_path / "authorized_devices.csv")
    service_principals = _read_optional_csv_rows(
        packet_path / "entra_service_principals.csv"
    )
    authorized_processes = _read_optional_csv_rows(
        packet_path / "authorized_processes.csv"
    )
    fci_access_events = _read_optional_csv_rows(packet_path / "fci_access_events.csv")

    control_id = control.get("control_id", "AC.L1-B.1.I")
    fci_site_name = control.get("fci_site_name")
    authorized_group_name = control.get("authorized_group_name")
    if not fci_site_name or not authorized_group_name:
        raise ValueError(
            "control_doc.md must include fci_site_name and authorized_group_name."
        )

    authorized_group_id = _resolve_authorized_group_id(groups, authorized_group_name)
    if not authorized_group_id:
        raise ValueError(
            f"Authorized group '{authorized_group_name}' was not found in entra_groups.csv."
        )

    user_by_id = {row.get("user_id", ""): row for row in users}
    members_by_group = _build_group_membership(group_members)
    authorized_members = members_by_group.get(authorized_group_id, set())
    user_ids_with_permissions: set[str] = set()

    relevant_permissions = [
        row for row in sp_permissions if row.get("site_name") == fci_site_name
    ]

    if not relevant_permissions:
        return {
            "control_id": control_id,
            "status": "NOT APPLICABLE",
            "findings": [
                {
                    "severity": "info",
                    "message": f"No SharePoint permissions found for site '{fci_site_name}'.",
                    "evidence_ref": "sharepoint_site_permissions.csv",
                }
            ],
            "evidence_refs": [
                "control_doc.md",
                "entra_users.csv",
                "entra_groups.csv",
                "entra_group_members.csv",
                "sharepoint_site_permissions.csv",
            ],
            "remediation": [],
            "context": {
                "fci_site_name": fci_site_name,
                "authorized_group_name": authorized_group_name,
                "effective_access_count": 0,
                "policy_rules": control.get("rules_text", []),
            },
        }

    effective_access: dict[str, list[EffectiveAccess]] = defaultdict(list)
    for row in relevant_permissions:
        principal_type = row.get("principal_type", "")
        principal_id = row.get("principal_id", "")
        role = row.get("role", "")
        row_num = int(row.get("_row", "0"))

        if principal_type == "User":
            user_ids_with_permissions.add(principal_id)
            effective_access[principal_id].append(
                EffectiveAccess(
                    user_id=principal_id,
                    source_row=row_num,
                    source_principal_type=principal_type,
                    source_principal_id=principal_id,
                    role=role,
                )
            )
        elif principal_type == "Group":
            for user_id in sorted(members_by_group.get(principal_id, set())):
                user_ids_with_permissions.add(user_id)
                effective_access[user_id].append(
                    EffectiveAccess(
                        user_id=user_id,
                        source_row=row_num,
                        source_principal_type=principal_type,
                        source_principal_id=principal_id,
                        role=role,
                    )
                )

    findings: list[dict[str, str]] = []
    objective_status: dict[str, str] = {
        "a_authorized_users_identified": "MET",
        "b_processes_identified": "NOT ASSESSED",
        "c_devices_identified": "NOT ASSESSED",
        "d_access_limited_to_authorized_users": "MET",
        "e_access_limited_to_authorized_processes": "NOT ASSESSED",
        "f_access_limited_to_authorized_devices": "NOT ASSESSED",
    }
    for user_id, sources in sorted(effective_access.items()):
        user = user_by_id.get(user_id)
        if not user:
            for src in sources:
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"User id '{user_id}' has effective access but does not exist "
                            "in entra_users.csv."
                        ),
                        "evidence_ref": (
                            "sharepoint_site_permissions.csv"
                            f":row:{src.source_row}"
                        ),
                    }
                )
            continue

        user_name = user.get("user_principal_name", user_id)
        is_enabled = user.get("account_enabled", "").lower() == "true"
        is_member_type = user.get("user_type") == "Member"
        is_authorized_member = user_id in authorized_members

        for src in sources:
            if not is_enabled:
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"Disabled account '{user_name}' has effective access to "
                            f"'{fci_site_name}'."
                        ),
                        "evidence_ref": (
                            "sharepoint_site_permissions.csv"
                            f":row:{src.source_row}"
                        ),
                    }
                )
            if control.get("block_guest_users", False) and not is_member_type:
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"Guest/external user '{user_name}' has effective access to "
                            f"'{fci_site_name}'."
                        ),
                        "evidence_ref": (
                            "sharepoint_site_permissions.csv"
                            f":row:{src.source_row}"
                        ),
                    }
                )
            if not is_authorized_member:
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"Unauthorized user '{user_name}' has effective access to "
                            f"'{fci_site_name}' and is not in '{authorized_group_name}'."
                        ),
                        "evidence_ref": (
                            "sharepoint_site_permissions.csv"
                            f":row:{src.source_row}"
                        ),
                    }
                )

    has_device_process_scope = bool(
        intune_devices
        or authorized_devices
        or service_principals
        or authorized_processes
        or fci_access_events
    )

    if has_device_process_scope:
        device_by_id = {row.get("device_id", ""): row for row in intune_devices}
        app_by_id = {row.get("app_id", ""): row for row in service_principals}
        authorized_device_ids = {
            row.get("device_id", "")
            for row in authorized_devices
            if row.get("site_name") == fci_site_name and row.get("device_id")
        }
        authorized_app_ids = {
            row.get("app_id", "")
            for row in authorized_processes
            if row.get("site_name") == fci_site_name and row.get("app_id")
        }

        objective_status["b_processes_identified"] = (
            "MET" if authorized_app_ids else "NOT MET"
        )
        objective_status["c_devices_identified"] = (
            "MET" if authorized_device_ids else "NOT MET"
        )
        objective_status["e_access_limited_to_authorized_processes"] = "MET"
        objective_status["f_access_limited_to_authorized_devices"] = "MET"

        if not authorized_app_ids:
            findings.append(
                {
                    "severity": "medium",
                    "message": (
                        "No authorized processes were identified for the FCI site "
                        f"'{fci_site_name}'."
                    ),
                    "evidence_ref": "authorized_processes.csv",
                }
            )
        if not authorized_device_ids:
            findings.append(
                {
                    "severity": "medium",
                    "message": (
                        "No authorized devices were identified for the FCI site "
                        f"'{fci_site_name}'."
                    ),
                    "evidence_ref": "authorized_devices.csv",
                }
            )

        for event in fci_access_events:
            if event.get("site_name") != fci_site_name:
                continue
            actor_type = event.get("actor_type", "")
            actor_id = event.get("actor_id", "")
            device_id = event.get("device_id", "")
            row_num = event.get("_row", "?")
            event_ref = f"fci_access_events.csv:row:{row_num}"

            if actor_type == "User" and actor_id not in user_ids_with_permissions:
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"User actor '{actor_id}' accessed '{fci_site_name}' in events "
                            "without being present in SharePoint permission-derived access."
                        ),
                        "evidence_ref": event_ref,
                    }
                )

            if actor_type == "App":
                app = app_by_id.get(actor_id)
                if not app:
                    objective_status["e_access_limited_to_authorized_processes"] = "NOT MET"
                    findings.append(
                        {
                            "severity": "high",
                            "message": (
                                f"Unknown process/app '{actor_id}' accessed '{fci_site_name}'."
                            ),
                            "evidence_ref": event_ref,
                        }
                    )
                else:
                    if not _is_true(app.get("account_enabled", "")):
                        objective_status[
                            "e_access_limited_to_authorized_processes"
                        ] = "NOT MET"
                        findings.append(
                            {
                                "severity": "high",
                                "message": (
                                    f"Disabled process/app '{app.get('display_name', actor_id)}' "
                                    f"accessed '{fci_site_name}'."
                                ),
                                "evidence_ref": event_ref,
                            }
                        )
                    if actor_id not in authorized_app_ids:
                        objective_status[
                            "e_access_limited_to_authorized_processes"
                        ] = "NOT MET"
                        findings.append(
                            {
                                "severity": "high",
                                "message": (
                                    f"Unauthorized process/app '{app.get('display_name', actor_id)}' "
                                    f"accessed '{fci_site_name}'."
                                ),
                                "evidence_ref": event_ref,
                            }
                        )

            if device_id:
                device = device_by_id.get(device_id)
                if not device:
                    objective_status["f_access_limited_to_authorized_devices"] = "NOT MET"
                    findings.append(
                        {
                            "severity": "high",
                            "message": (
                                f"Unknown device '{device_id}' accessed '{fci_site_name}'."
                            ),
                            "evidence_ref": event_ref,
                        }
                    )
                else:
                    if not _is_true(device.get("managed", "")):
                        objective_status[
                            "f_access_limited_to_authorized_devices"
                        ] = "NOT MET"
                        findings.append(
                            {
                                "severity": "high",
                                "message": (
                                    f"Unmanaged device '{device.get('device_name', device_id)}' "
                                    f"accessed '{fci_site_name}'."
                                ),
                                "evidence_ref": event_ref,
                            }
                        )
                    if not _is_true(device.get("compliant", "")):
                        objective_status[
                            "f_access_limited_to_authorized_devices"
                        ] = "NOT MET"
                        findings.append(
                            {
                                "severity": "high",
                                "message": (
                                    f"Non-compliant device '{device.get('device_name', device_id)}' "
                                    f"accessed '{fci_site_name}'."
                                ),
                                "evidence_ref": event_ref,
                            }
                        )
                    if device_id not in authorized_device_ids:
                        objective_status[
                            "f_access_limited_to_authorized_devices"
                        ] = "NOT MET"
                        findings.append(
                            {
                                "severity": "high",
                                "message": (
                                    f"Unauthorized device '{device.get('device_name', device_id)}' "
                                    f"accessed '{fci_site_name}'."
                                ),
                                "evidence_ref": event_ref,
                            }
                        )

    status = "MET" if not findings else "NOT MET"
    remediation: list[str] = []
    if status == "NOT MET":
        remediation = [
            f"Remove non-approved principals from SharePoint site '{fci_site_name}' permissions.",
            f"Ensure all effective users are members of Entra group '{authorized_group_name}'.",
            "Disable or remove access for inactive accounts.",
            "Validate guest/external user restrictions for FCI access.",
            "Require Intune-managed and compliant devices for FCI data access.",
            "Restrict app/service principal access to explicitly approved processes.",
        ]

    evidence_refs = [
        "control_doc.md",
        "entra_users.csv",
        "entra_groups.csv",
        "entra_group_members.csv",
        "sharepoint_site_permissions.csv",
    ]
    optional_refs = [
        ("intune_devices.csv", intune_devices),
        ("authorized_devices.csv", authorized_devices),
        ("entra_service_principals.csv", service_principals),
        ("authorized_processes.csv", authorized_processes),
        ("fci_access_events.csv", fci_access_events),
    ]
    for filename, rows in optional_refs:
        if rows:
            evidence_refs.append(filename)

    return {
        "control_id": control_id,
        "status": status,
        "findings": findings,
        "evidence_refs": evidence_refs,
        "remediation": remediation,
        "context": {
            "fci_site_name": fci_site_name,
            "authorized_group_name": authorized_group_name,
            "effective_access_count": len(effective_access),
            "policy_rules": control.get("rules_text", []),
            "assessment_objectives": objective_status,
        },
    }


def build_report_markdown(result: dict[str, Any]) -> str:
    context = result.get("context", {})
    rules = context.get("policy_rules", [])
    findings = result.get("findings", [])
    remediation = result.get("remediation", [])
    objective_status = context.get("assessment_objectives", {})

    lines = [
        f"# AC.L1-B.1.I Assessment Report ({result.get('status')})",
        "",
        "## What Was Assessed",
        (
            f"- Control: `{result.get('control_id')}` on SharePoint site "
            f"`{context.get('fci_site_name', 'Unknown')}`."
        ),
        (
            f"- Authorized group baseline: "
            f"`{context.get('authorized_group_name', 'Unknown')}`."
        ),
        (
            f"- Effective users evaluated: "
            f"`{context.get('effective_access_count', 0)}`."
        ),
        "",
        "## Rules Applied",
    ]
    if rules:
        lines.extend([f"- {rule}" for rule in rules])
    else:
        lines.append("- Rules were read from `control_doc.md`.")

    lines.extend(["", "## Evidence Used"])
    lines.extend([f"- `{item}`" for item in result.get("evidence_refs", [])])

    if objective_status:
        lines.extend(["", "## Assessment Objectives (NIST SP 800-171A)"])
        lines.extend(
            [
                f"- `{objective}`: `{status}`"
                for objective, status in objective_status.items()
            ]
        )

    lines.extend(["", "## Findings"])
    if findings:
        for idx, finding in enumerate(findings, start=1):
            lines.append(
                f"{idx}. {finding['message']} (evidence: `{finding['evidence_ref']}`)"
            )
    else:
        lines.append("- No findings. All effective users satisfied the configured rules.")

    lines.extend(["", "## Recommended Remediation"])
    if remediation:
        lines.extend([f"- {step}" for step in remediation])
    else:
        lines.append("- None required for current result.")

    return "\n".join(lines) + "\n"


def write_outputs(packet_dir: str | Path, result: dict[str, Any]) -> tuple[Path, Path]:
    packet_path = Path(packet_dir).resolve()
    output_dir = packet_path / "outputs"
    output_dir.mkdir(parents=True, exist_ok=True)

    scorecard_path = output_dir / "scorecard.json"
    report_path = output_dir / "report.md"

    with scorecard_path.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "control_id": result["control_id"],
                "status": result["status"],
                "findings": result["findings"],
                "evidence_refs": result["evidence_refs"],
                "remediation": result["remediation"],
            },
            handle,
            indent=2,
        )

    report_path.write_text(build_report_markdown(result), encoding="utf-8")
    return scorecard_path, report_path

