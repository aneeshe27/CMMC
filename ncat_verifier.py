"""Deterministic verifier for CMMC AC.L2-3.1.1 demo evidence packets.

The verifier intentionally separates adapter-specific evidence loading from the
compliance decision. Microsoft CSV exports and Okta/Box/Jamf API-style JSON
normalize into the same evidence model before objective checks run.
"""

from __future__ import annotations

import csv
import json
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class EffectiveAccess:
    user_id: str
    source_row: int | None
    source_principal_type: str
    source_principal_id: str
    role: str
    evidence_ref: str


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


def _read_microsoft_access_events(packet_path: Path) -> tuple[list[dict[str, str]], str]:
    cui_path = packet_path / "cui_access_events.csv"
    legacy_path = packet_path / "fci_access_events.csv"
    if cui_path.exists():
        return _read_csv_rows(cui_path), cui_path.name
    if legacy_path.exists():
        return _read_csv_rows(legacy_path), legacy_path.name
    return [], cui_path.name


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing evidence file: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _is_true(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() == "true"


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
            if ". " in line and line.split(". ", 1)[0].isdigit():
                parsed["rules_text"].append(line)

    rules_blob = " ".join(parsed["rules_text"]).lower()
    parsed["block_guest_users"] = ("guest not allowed" in rules_blob) or (
        "external identities are prohibited" in rules_blob
    )
    parsed["resource_name"] = (
        parsed.get("cui_resource_name")
        or parsed.get("fci_site_name")
        or parsed.get("resource_name")
    )
    return parsed


def _detect_source_stack(packet_path: Path) -> str:
    if (
        (packet_path / "okta_users.json").exists()
        or (packet_path / "box_collaborations.json").exists()
        or (packet_path / "jamf_devices.json").exists()
    ):
        return "Okta + Box + Jamf"
    return "Microsoft Entra + SharePoint + Intune"


def _build_group_membership(group_rows: list[dict[str, str]]) -> dict[str, set[str]]:
    members_by_group: dict[str, set[str]] = defaultdict(set)
    for row in group_rows:
        group_id = row.get("group_id", "")
        user_id = row.get("user_id", "")
        if group_id and user_id:
            members_by_group[group_id].add(user_id)
    return members_by_group


def _resolve_authorized_group_id(
    groups: dict[str, dict[str, Any]], authorized_group_name: str
) -> str | None:
    for group_id, group in groups.items():
        if group.get("group_name") == authorized_group_name:
            return group_id
    return None


def _normalize_microsoft_packet(packet_path: Path, control: dict[str, Any]) -> dict[str, Any]:
    users = _read_csv_rows(packet_path / "entra_users.csv")
    groups = _read_csv_rows(packet_path / "entra_groups.csv")
    group_members = _read_csv_rows(packet_path / "entra_group_members.csv")
    permissions = _read_csv_rows(packet_path / "sharepoint_site_permissions.csv")
    intune_devices = _read_optional_csv_rows(packet_path / "intune_devices.csv")
    authorized_devices = _read_optional_csv_rows(packet_path / "authorized_devices.csv")
    service_principals = _read_optional_csv_rows(
        packet_path / "entra_service_principals.csv"
    )
    authorized_processes = _read_optional_csv_rows(
        packet_path / "authorized_processes.csv"
    )
    access_events, access_events_filename = _read_microsoft_access_events(packet_path)

    resource_name = control.get("resource_name")
    normalized_permissions = [
        {
            "resource_name": row.get("site_name", ""),
            "principal_type": row.get("principal_type", ""),
            "principal_id": row.get("principal_id", ""),
            "role": row.get("role", ""),
            "evidence_ref": f"sharepoint_site_permissions.csv:row:{row.get('_row', '?')}",
            "source_id": row.get("_row", ""),
        }
        for row in permissions
    ]
    normalized_events = [
        {
            "resource_name": row.get("site_name", ""),
            "actor_type": row.get("actor_type", ""),
            "actor_id": row.get("actor_id", ""),
            "device_id": row.get("device_id", ""),
            "action": row.get("action", ""),
            "timestamp": row.get("timestamp", ""),
            "evidence_ref": f"{access_events_filename}:row:{row.get('_row', '?')}",
        }
        for row in access_events
    ]

    return {
        "source_stack": "Microsoft Entra + SharePoint + Intune",
        "control": control,
        "users_by_id": {
            row.get("user_id", ""): {
                "user_id": row.get("user_id", ""),
                "user_name": row.get("user_principal_name", row.get("user_id", "")),
                "display_name": row.get("display_name", ""),
                "account_enabled": _is_true(row.get("account_enabled")),
                "user_type": row.get("user_type", ""),
                "source_ref": f"entra_users.csv:row:{row.get('_row', '?')}",
            }
            for row in users
            if row.get("user_id")
        },
        "groups": {
            row.get("group_id", ""): {
                "group_id": row.get("group_id", ""),
                "group_name": row.get("group_name", ""),
                "source_ref": f"entra_groups.csv:row:{row.get('_row', '?')}",
            }
            for row in groups
            if row.get("group_id")
        },
        "members_by_group": _build_group_membership(group_members),
        "permissions": normalized_permissions,
        "devices_by_id": {
            row.get("device_id", ""): {
                "device_id": row.get("device_id", ""),
                "device_name": row.get("device_name", row.get("device_id", "")),
                "managed": _is_true(row.get("managed")),
                "compliant": _is_true(row.get("compliant")),
                "source_ref": f"intune_devices.csv:row:{row.get('_row', '?')}",
            }
            for row in intune_devices
            if row.get("device_id")
        },
        "authorized_device_ids": {
            row.get("device_id", "")
            for row in authorized_devices
            if row.get("site_name") == resource_name and row.get("device_id")
        },
        "apps_by_id": {
            row.get("app_id", ""): {
                "app_id": row.get("app_id", ""),
                "display_name": row.get("display_name", row.get("app_id", "")),
                "account_enabled": _is_true(row.get("account_enabled")),
                "source_ref": f"entra_service_principals.csv:row:{row.get('_row', '?')}",
            }
            for row in service_principals
            if row.get("app_id")
        },
        "authorized_app_ids": {
            row.get("app_id", "")
            for row in authorized_processes
            if row.get("site_name") == resource_name and row.get("app_id")
        },
        "events": normalized_events,
        "evidence_refs": [
            "control_doc.md",
            "entra_users.csv",
            "entra_groups.csv",
            "entra_group_members.csv",
            "sharepoint_site_permissions.csv",
        ]
        + [
            filename
            for filename, rows in [
                ("intune_devices.csv", intune_devices),
                ("authorized_devices.csv", authorized_devices),
                ("entra_service_principals.csv", service_principals),
                ("authorized_processes.csv", authorized_processes),
                (access_events_filename, access_events),
            ]
            if rows
        ],
        "normalization_summary": {
            "raw_format": "CSV exports modeled after Microsoft admin center exports",
            "users": len(users),
            "groups": len(groups),
            "permissions": len(permissions),
            "devices": len(intune_devices),
            "processes": len(service_principals),
            "access_events": len(access_events),
            "resource_permission_edges": len(
                [row for row in normalized_permissions if row["resource_name"] == resource_name]
            ),
        },
    }


def _jamf_extension_value(device: dict[str, Any], name: str) -> str:
    for attr in device.get("extension_attributes", []):
        if attr.get("name") == name:
            return str(attr.get("value", ""))
    return ""


def _normalize_okta_box_jamf_packet(
    packet_path: Path, control: dict[str, Any]
) -> dict[str, Any]:
    okta_users = _read_json(packet_path / "okta_users.json")
    okta_groups = _read_json(packet_path / "okta_groups.json")
    box_collaborations = _read_json(packet_path / "box_collaborations.json")
    jamf_devices = _read_json(packet_path / "jamf_devices.json")
    authorization_policy = _read_json(packet_path / "authorization_policy.json")
    okta_apps = _read_json(packet_path / "okta_apps.json")
    access_events = _read_json(packet_path / "access_events.json")

    resource_name = control.get("resource_name")
    policy_resources = authorization_policy.get("resources", [])
    resource_policy = next(
        (
            item
            for item in policy_resources
            if item.get("resource_name") == resource_name
        ),
        {},
    )

    users_by_id = {}
    for item in okta_users.get("items", []):
        profile = item.get("profile", {})
        user_type = item.get("type", {}).get("name", "")
        users_by_id[item.get("id", "")] = {
            "user_id": item.get("id", ""),
            "user_name": profile.get("login", item.get("id", "")),
            "display_name": profile.get("displayName", ""),
            "account_enabled": item.get("status") == "ACTIVE",
            "user_type": user_type,
            "source_ref": f"okta_users.json:items:{item.get('id', '')}",
        }

    groups: dict[str, dict[str, Any]] = {}
    members_by_group: dict[str, set[str]] = defaultdict(set)
    for group in okta_groups.get("groups", []):
        group_id = group.get("id", "")
        groups[group_id] = {
            "group_id": group_id,
            "group_name": group.get("profile", {}).get("name", group_id),
            "source_ref": f"okta_groups.json:groups:{group_id}",
        }
        for embedded_user in group.get("_embedded", {}).get("users", []):
            if embedded_user.get("id"):
                members_by_group[group_id].add(embedded_user["id"])

    normalized_permissions = []
    for entry in box_collaborations.get("entries", []):
        item = entry.get("item", {})
        principal = entry.get("accessible_by", {})
        principal_type = "Group" if principal.get("type") == "group" else "User"
        normalized_permissions.append(
            {
                "resource_name": item.get("name", ""),
                "resource_id": item.get("id", ""),
                "principal_type": principal_type,
                "principal_id": principal.get("id", ""),
                "role": entry.get("role", ""),
                "evidence_ref": f"box_collaborations.json:entries:{entry.get('id', '')}",
                "source_id": entry.get("id", ""),
            }
        )

    devices_by_id = {}
    for computer in jamf_devices.get("computers", []):
        compliance = _jamf_extension_value(computer, "complianceStatus").lower()
        devices_by_id[computer.get("id", "")] = {
            "device_id": computer.get("id", ""),
            "device_name": computer.get("name", computer.get("id", "")),
            "managed": computer.get("management_status") == "Managed",
            "compliant": compliance == "compliant",
            "source_ref": f"jamf_devices.json:computers:{computer.get('id', '')}",
        }

    apps_by_id = {}
    for app in okta_apps.get("applications", []):
        apps_by_id[app.get("id", "")] = {
            "app_id": app.get("id", ""),
            "display_name": app.get("label", app.get("id", "")),
            "account_enabled": app.get("status") == "ACTIVE",
            "source_ref": f"okta_apps.json:applications:{app.get('id', '')}",
        }

    normalized_events = []
    for event in access_events.get("events", []):
        actor = event.get("actor", {})
        target = event.get("target", {})
        client = event.get("client", {})
        normalized_events.append(
            {
                "resource_name": target.get("displayName", ""),
                "resource_id": target.get("id", ""),
                "actor_type": actor.get("type", ""),
                "actor_id": actor.get("id", ""),
                "device_id": client.get("device", {}).get("id", ""),
                "action": event.get("eventType", ""),
                "timestamp": event.get("published", ""),
                "evidence_ref": f"access_events.json:events:{event.get('uuid', '')}",
            }
        )

    return {
        "source_stack": "Okta + Box + Jamf",
        "control": control,
        "users_by_id": users_by_id,
        "groups": groups,
        "members_by_group": members_by_group,
        "permissions": normalized_permissions,
        "devices_by_id": devices_by_id,
        "authorized_device_ids": set(resource_policy.get("allowed_device_ids", [])),
        "apps_by_id": apps_by_id,
        "authorized_app_ids": set(resource_policy.get("allowed_process_ids", [])),
        "events": normalized_events,
        "evidence_refs": [
            "control_doc.md",
            "okta_users.json",
            "okta_groups.json",
            "box_collaborations.json",
            "jamf_devices.json",
            "authorization_policy.json",
            "okta_apps.json",
            "access_events.json",
        ],
        "normalization_summary": {
            "raw_format": (
                "API-style JSON: nested Okta profiles/groups, Box collaboration "
                "objects, and Jamf device extension attributes"
            ),
            "users": len(users_by_id),
            "groups": len(groups),
            "permissions": len(normalized_permissions),
            "devices": len(devices_by_id),
            "processes": len(apps_by_id),
            "access_events": len(normalized_events),
            "resource_permission_edges": len(
                [
                    row
                    for row in normalized_permissions
                    if row["resource_name"] == resource_name
                ]
            ),
        },
    }


def _load_normalized_evidence(packet_path: Path, control: dict[str, Any]) -> dict[str, Any]:
    source_stack = _detect_source_stack(packet_path)
    if source_stack == "Okta + Box + Jamf":
        return _normalize_okta_box_jamf_packet(packet_path, control)
    return _normalize_microsoft_packet(packet_path, control)


def _action_for_finding(finding: dict[str, str], source_stack: str) -> dict[str, str]:
    message = finding.get("message", "")
    if "Unauthorized user" in message or "Guest/external user" in message:
        if source_stack.startswith("Microsoft"):
            api = "DELETE /groups/{group-id}/members/{user-id}/$ref"
            owner = "IT Security Owner + CUI Data Owner"
        else:
            api = "DELETE /api/v1/groups/{groupId}/users/{userId}"
            owner = "IT Security Owner + CUI Data Owner"
        return {
            "proposed_action": "Remove unauthorized principal from the CUI-authorized group.",
            "candidate_api_call": api,
            "risk": "May disrupt business access if the group membership is legitimate but undocumented.",
            "required_approval": owner,
        }
    if "device" in message.lower():
        if source_stack.startswith("Microsoft"):
            api = "PATCH /deviceManagement/managedDevices/{managedDeviceId}"
        else:
            api = "POST /api/v1/computers-inventory/{id}/extension-attributes"
        return {
            "proposed_action": (
                "Block CUI access from the device or start the device authorization workflow."
            ),
            "candidate_api_call": api,
            "risk": "Device may be legitimate but missing approval or posture evidence.",
            "required_approval": "IT Security Owner + Endpoint Owner",
        }
    if "process/app" in message:
        if source_stack.startswith("Microsoft"):
            api = "PATCH /applications/{id}"
        else:
            api = "POST /api/v1/apps/{appId}/lifecycle/deactivate"
        return {
            "proposed_action": "Disable, remove, or formally authorize the process path.",
            "candidate_api_call": api,
            "risk": "May interrupt automated business workflows.",
            "required_approval": "IT Security Owner + Application Owner",
        }
    return {
        "proposed_action": "Review the referenced evidence and update authorization policy.",
        "candidate_api_call": "Convert finding to ticket",
        "risk": "Manual classification required before technical change.",
        "required_approval": "Control Owner",
    }


def verify_packet(packet_dir: str | Path) -> dict[str, Any]:
    start = time.perf_counter()
    packet_path = Path(packet_dir).resolve()
    control = _parse_control_doc(packet_path / "control_doc.md")
    evidence = _load_normalized_evidence(packet_path, control)

    control_id = control.get("control_id", "AC.L2-3.1.1")
    resource_name = control.get("resource_name")
    authorized_group_name = control.get("authorized_group_name")
    if not resource_name or not authorized_group_name:
        raise ValueError(
            "control_doc.md must include cui_resource_name/resource_name and authorized_group_name."
        )

    users_by_id = evidence["users_by_id"]
    groups = evidence["groups"]
    members_by_group = evidence["members_by_group"]
    authorized_group_id = _resolve_authorized_group_id(groups, authorized_group_name)
    if not authorized_group_id:
        raise ValueError(
            f"Authorized group '{authorized_group_name}' was not found in normalized groups."
        )

    authorized_members = members_by_group.get(authorized_group_id, set())
    user_ids_with_permissions: set[str] = set()
    relevant_permissions = [
        row for row in evidence["permissions"] if row.get("resource_name") == resource_name
    ]

    if not relevant_permissions:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "control_id": control_id,
            "status": "NOT APPLICABLE",
            "findings": [
                {
                    "severity": "info",
                    "message": f"No permissions found for CUI resource '{resource_name}'.",
                    "evidence_ref": "normalized:permissions",
                }
            ],
            "evidence_refs": evidence["evidence_refs"],
            "remediation": [],
            "proposed_actions": [],
            "context": {
                "source_stack": evidence["source_stack"],
                "resource_name": resource_name,
                "authorized_group_name": authorized_group_name,
                "effective_access_count": 0,
                "policy_rules": control.get("rules_text", []),
                "normalization_summary": evidence["normalization_summary"],
                "runtime_metrics": {"verification_elapsed_ms": elapsed_ms},
            },
        }

    effective_access: dict[str, list[EffectiveAccess]] = defaultdict(list)
    for row in relevant_permissions:
        principal_type = row.get("principal_type", "")
        principal_id = row.get("principal_id", "")
        role = row.get("role", "")
        evidence_ref = row.get("evidence_ref", "normalized:permissions")

        if principal_type == "User":
            user_ids_with_permissions.add(principal_id)
            effective_access[principal_id].append(
                EffectiveAccess(
                    user_id=principal_id,
                    source_row=None,
                    source_principal_type=principal_type,
                    source_principal_id=principal_id,
                    role=role,
                    evidence_ref=evidence_ref,
                )
            )
        elif principal_type == "Group":
            for user_id in sorted(members_by_group.get(principal_id, set())):
                user_ids_with_permissions.add(user_id)
                effective_access[user_id].append(
                    EffectiveAccess(
                        user_id=user_id,
                        source_row=None,
                        source_principal_type=principal_type,
                        source_principal_id=principal_id,
                        role=role,
                        evidence_ref=evidence_ref,
                    )
                )

    findings: list[dict[str, str]] = []
    objective_status: dict[str, str] = {
        "a_authorized_users_identified": "MET",
        "b_authorized_processes_identified": "NOT ASSESSED",
        "c_authorized_devices_identified": "NOT ASSESSED",
        "d_access_limited_to_authorized_users": "MET",
        "e_access_limited_to_authorized_processes": "NOT ASSESSED",
        "f_access_limited_to_authorized_devices": "NOT ASSESSED",
    }

    for user_id, sources in sorted(effective_access.items()):
        user = users_by_id.get(user_id)
        if not user:
            objective_status["a_authorized_users_identified"] = "NOT MET"
            objective_status["d_access_limited_to_authorized_users"] = "NOT MET"
            for src in sources:
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"User id '{user_id}' has effective access but does not exist "
                            "in the normalized user inventory."
                        ),
                        "evidence_ref": src.evidence_ref,
                    }
                )
            continue

        user_name = user.get("user_name", user_id)
        is_enabled = bool(user.get("account_enabled"))
        is_member_type = user.get("user_type") == "Member"
        is_authorized_member = user_id in authorized_members

        for src in sources:
            access_path = ""
            if src.source_principal_type == "Group":
                access_path = f" through group '{src.source_principal_id}'"
            if not is_enabled:
                objective_status["d_access_limited_to_authorized_users"] = "NOT MET"
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"Disabled account '{user_name}' has effective access to "
                            f"'{resource_name}'{access_path}."
                        ),
                        "evidence_ref": src.evidence_ref,
                    }
                )
            if control.get("block_guest_users", False) and not is_member_type:
                objective_status["d_access_limited_to_authorized_users"] = "NOT MET"
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"Guest/external user '{user_name}' has effective access to "
                            f"'{resource_name}'{access_path}."
                        ),
                        "evidence_ref": src.evidence_ref,
                    }
                )
            if not is_authorized_member:
                objective_status["d_access_limited_to_authorized_users"] = "NOT MET"
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"Unauthorized user '{user_name}' has effective access to "
                            f"'{resource_name}'{access_path} and is not in "
                            f"'{authorized_group_name}'."
                        ),
                        "evidence_ref": src.evidence_ref,
                    }
                )

    devices_by_id = evidence["devices_by_id"]
    apps_by_id = evidence["apps_by_id"]
    authorized_device_ids = evidence["authorized_device_ids"]
    authorized_app_ids = evidence["authorized_app_ids"]
    has_device_process_scope = bool(
        devices_by_id or authorized_device_ids or apps_by_id or authorized_app_ids or evidence["events"]
    )

    if has_device_process_scope:
        objective_status["b_authorized_processes_identified"] = (
            "MET" if authorized_app_ids else "NOT MET"
        )
        objective_status["c_authorized_devices_identified"] = (
            "MET" if authorized_device_ids else "NOT MET"
        )
        objective_status["e_access_limited_to_authorized_processes"] = "MET"
        objective_status["f_access_limited_to_authorized_devices"] = "MET"

        if not authorized_app_ids:
            findings.append(
                {
                    "severity": "medium",
                    "message": (
                        "No authorized processes were identified for the CUI resource "
                        f"'{resource_name}'."
                    ),
                    "evidence_ref": "normalized:authorized_processes",
                }
            )
        if not authorized_device_ids:
            findings.append(
                {
                    "severity": "medium",
                    "message": (
                        "No authorized devices were identified for the CUI resource "
                        f"'{resource_name}'."
                    ),
                    "evidence_ref": "normalized:authorized_devices",
                }
            )

        for event in evidence["events"]:
            if event.get("resource_name") != resource_name:
                continue
            actor_type = event.get("actor_type", "")
            actor_id = event.get("actor_id", "")
            device_id = event.get("device_id", "")
            event_ref = event.get("evidence_ref", "normalized:events")

            if actor_type == "User" and actor_id not in user_ids_with_permissions:
                objective_status["d_access_limited_to_authorized_users"] = "NOT MET"
                findings.append(
                    {
                        "severity": "high",
                        "message": (
                            f"User actor '{actor_id}' accessed '{resource_name}' in events "
                            "without being present in permission-derived access."
                        ),
                        "evidence_ref": event_ref,
                    }
                )

            if actor_type == "App":
                app = apps_by_id.get(actor_id)
                if not app:
                    objective_status["e_access_limited_to_authorized_processes"] = "NOT MET"
                    findings.append(
                        {
                            "severity": "high",
                            "message": f"Unknown process/app '{actor_id}' accessed '{resource_name}'.",
                            "evidence_ref": event_ref,
                        }
                    )
                else:
                    if not app.get("account_enabled"):
                        objective_status[
                            "e_access_limited_to_authorized_processes"
                        ] = "NOT MET"
                        findings.append(
                            {
                                "severity": "high",
                                "message": (
                                    f"Disabled process/app '{app.get('display_name', actor_id)}' "
                                    f"accessed '{resource_name}'."
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
                                    f"accessed '{resource_name}'."
                                ),
                                "evidence_ref": event_ref,
                            }
                        )

            if device_id:
                device = devices_by_id.get(device_id)
                if not device:
                    objective_status["f_access_limited_to_authorized_devices"] = "NOT MET"
                    findings.append(
                        {
                            "severity": "high",
                            "message": f"Unknown device '{device_id}' accessed '{resource_name}'.",
                            "evidence_ref": event_ref,
                        }
                    )
                else:
                    if not device.get("managed"):
                        objective_status[
                            "f_access_limited_to_authorized_devices"
                        ] = "NOT MET"
                        findings.append(
                            {
                                "severity": "high",
                                "message": (
                                    f"Unmanaged device '{device.get('device_name', device_id)}' "
                                    f"accessed '{resource_name}'."
                                ),
                                "evidence_ref": event_ref,
                            }
                        )
                    if not device.get("compliant"):
                        objective_status[
                            "f_access_limited_to_authorized_devices"
                        ] = "NOT MET"
                        findings.append(
                            {
                                "severity": "high",
                                "message": (
                                    f"Non-compliant device '{device.get('device_name', device_id)}' "
                                    f"accessed '{resource_name}'."
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
                                    f"accessed '{resource_name}'."
                                ),
                                "evidence_ref": event_ref,
                            }
                        )

    status = "MET" if not findings else "NOT MET"
    remediation: list[str] = []
    proposed_actions: list[dict[str, str]] = []
    if status == "NOT MET":
        remediation = [
            f"Remove non-approved principals from CUI resource '{resource_name}' permissions.",
            f"Ensure all effective users are members of group '{authorized_group_name}'.",
            "Disable or remove access for inactive or external accounts unless formally authorized.",
            "Require managed, compliant, and explicitly authorized devices for CUI access.",
            "Restrict app/service access to explicitly approved processes.",
        ]
        proposed_actions = [
            {"finding": finding["message"], **_action_for_finding(finding, evidence["source_stack"])}
            for finding in findings
        ]

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    normalization_summary = evidence["normalization_summary"]

    return {
        "control_id": control_id,
        "status": status,
        "findings": findings,
        "evidence_refs": evidence["evidence_refs"],
        "remediation": remediation,
        "proposed_actions": proposed_actions,
        "context": {
            "source_stack": evidence["source_stack"],
            "resource_name": resource_name,
            "authorized_group_name": authorized_group_name,
            "effective_access_count": len(effective_access),
            "policy_rules": control.get("rules_text", []),
            "assessment_objectives": objective_status,
            "normalization_summary": normalization_summary,
            "runtime_metrics": {
                "verification_elapsed_ms": elapsed_ms,
                "users_evaluated": len(users_by_id),
                "devices_evaluated": len(devices_by_id),
                "processes_evaluated": len(apps_by_id),
                "permission_edges_evaluated": normalization_summary.get(
                    "resource_permission_edges", 0
                ),
                "access_events_evaluated": normalization_summary.get("access_events", 0),
                "findings_found": len(findings),
            },
        },
    }


def build_report_markdown(result: dict[str, Any]) -> str:
    context = result.get("context", {})
    rules = context.get("policy_rules", [])
    findings = result.get("findings", [])
    remediation = result.get("remediation", [])
    proposed_actions = result.get("proposed_actions", [])
    objective_status = context.get("assessment_objectives", {})

    lines = [
        f"# AC.L2-3.1.1 Assessment Report ({result.get('status')})",
        "",
        "## What Was Assessed",
        f"- Control: `{result.get('control_id')}` on CUI resource `{context.get('resource_name', 'Unknown')}`.",
        f"- Source stack: `{context.get('source_stack', 'Unknown')}`.",
        f"- Authorized group baseline: `{context.get('authorized_group_name', 'Unknown')}`.",
        f"- Effective users evaluated: `{context.get('effective_access_count', 0)}`.",
        "",
        "## Normalization Summary",
    ]
    for key, value in context.get("normalization_summary", {}).items():
        lines.append(f"- `{key}`: `{value}`")

    lines.extend(["", "## Runtime Metrics"])
    for key, value in context.get("runtime_metrics", {}).items():
        lines.append(f"- `{key}`: `{value}`")

    lines.extend(["", "## Rules Applied"])
    if rules:
        lines.extend([f"- {rule}" for rule in rules])
    else:
        lines.append("- Rules were read from `control_doc.md`.")

    lines.extend(["", "## Evidence Used"])
    lines.extend([f"- `{item}`" for item in result.get("evidence_refs", [])])

    if objective_status:
        lines.extend(["", "## Assessment Objectives"])
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
        lines.append("- No findings. Effective access satisfied the configured rules.")

    lines.extend(["", "## Recommended Remediation"])
    if remediation:
        lines.extend([f"- {step}" for step in remediation])
    else:
        lines.append("- None required for current result.")

    if proposed_actions:
        lines.extend(["", "## Human-Approved Candidate Actions"])
        for idx, action in enumerate(proposed_actions, start=1):
            lines.extend(
                [
                    f"{idx}. {action.get('proposed_action')}",
                    f"   - Finding: `{action.get('finding')}`",
                    f"   - Candidate API call: `{action.get('candidate_api_call')}`",
                    f"   - Risk: {action.get('risk')}",
                    f"   - Required approval: {action.get('required_approval')}",
                ]
            )

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
                "proposed_actions": result["proposed_actions"],
                "context": result["context"],
            },
            handle,
            indent=2,
        )

    report_path.write_text(build_report_markdown(result), encoding="utf-8")
    return scorecard_path, report_path
