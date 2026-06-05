# NexGen CMMC Level 2 Demo Agent

A deterministic verifier and demo agent for **CMMC Level 2** control
**AC.L2-3.1.1** (Authorized Access Control). It evaluates whether only
authorized users, processes, and devices have effective access to CUI.

## Overview

This project provides:

- **Deterministic verification**: Explainable checks using customer evidence packets.
- **Multi-stack evidence normalization**: Microsoft CSV exports and Okta/Box/Jamf
  API-style JSON normalize into the same internal model.
- **Assessment-objective mapping**: Objective-level status for authorized users,
  processes, devices, and access limitation.
- **Streamlit demo app**: Evidence preview, normalization summary, findings,
  runtime metrics, roadmap, and output downloads.
- **AI-assisted remediation**: On `NOT MET`, OpenAI can generate concise
  remediation guidance from deterministic findings.
- **Human-approved candidate actions**: Proposed API calls are shown for review,
  but no change is executed automatically.

## Control In Scope

| Field | Value |
|-------|-------|
| Control ID | AC.L2-3.1.1 |
| Control Name | Authorized Access Control |
| Requirement | Limit system access to authorized users, processes acting on behalf of authorized users, and devices |
| Demo Scope | One Level 2 access-control requirement in depth, plus a Level 2 roadmap view |

## Quick Start

### Prerequisites

- Python 3.10+
- Streamlit
- Optional: `OPENAI_API_KEY` for LLM remediation generation

### Install Dependencies

```bash
pip install streamlit
```

### Run the Streamlit Demo

```bash
streamlit run streamlit_demo_dashboard.py
```

In the app:

- Select the Microsoft CSV packet or the Okta/Box/Jamf JSON packet.
- Preview the raw evidence shape.
- Click **Verify AC.L2-3.1.1**.
- Review normalization, runtime metrics, objective statuses, findings, and
  candidate remediation actions.

### Run Verification From CLI

```python
from ac_l1_b_1_i_verifier import verify_packet, write_outputs

result = verify_packet("packet_ac_l2_3_1_1_microsoft")
write_outputs("packet_ac_l2_3_1_1_microsoft", result)
```

## Evidence Packets

### Microsoft Packet

Folder: `packet_ac_l2_3_1_1_microsoft/`

Raw format: flat CSV exports modeled after Microsoft admin center exports.

| File | Description |
|------|-------------|
| `control_doc.md` | CUI scope, authorized group, and policy rules |
| `entra_users.csv` | User inventory |
| `entra_groups.csv` | Group catalog |
| `entra_group_members.csv` | Group membership mapping |
| `sharepoint_site_permissions.csv` | SharePoint resource permissions |
| `intune_devices.csv` | Device posture inventory |
| `authorized_devices.csv` | Approved device list |
| `entra_service_principals.csv` | Process/app identities |
| `authorized_processes.csv` | Approved process list |
| `fci_access_events.csv` | Access events linking actors and devices |

### Okta/Box/Jamf Packet

Folder: `packet_ac_l2_3_1_1_okta_box_jamf/`

Raw format: nested API-style JSON, intentionally unlike the Microsoft CSV packet.

| File | Description |
|------|-------------|
| `control_doc.md` | CUI scope, authorized group, and policy rules |
| `okta_users.json` | Okta-style user objects with nested profiles and types |
| `okta_groups.json` | Okta-style group objects with embedded users |
| `box_collaborations.json` | Box collaboration objects with item and principal models |
| `jamf_devices.json` | Jamf-style computer inventory with extension attributes |
| `authorization_policy.json` | Approved group, device, and process policy |
| `okta_apps.json` | Application/process inventory |
| `access_events.json` | API-style activity events with actor, target, and client device |

Both packets normalize into:

- users
- groups
- group memberships
- resources
- permissions
- devices
- authorized devices
- processes
- authorized processes
- access events

## What The Verifier Checks

- Expands group-based permissions into effective user access.
- Verifies effective users exist, are enabled/active, are internal members, and
  belong to the authorized CUI group.
- Verifies processes/apps are enabled and explicitly authorized.
- Verifies devices are managed, compliant, and explicitly authorized.
- Maps results to AC.L2-3.1.1 assessment objectives:
  - authorized users identified
  - authorized processes identified
  - authorized devices identified
  - access limited to authorized users
  - access limited to authorized processes
  - access limited to authorized devices

## Demo Injects

Use one inject at a time for a clean video narrative.

### Microsoft Unauthorized User

Append to `packet_ac_l2_3_1_1_microsoft/sharepoint_site_permissions.csv`:

```csv
Contracts-CUI,User,08f4db5b-3f87-4ce8-b41e-e3268fe55707,Read
```

Expected result: `NOT MET`; guest/external user and unauthorized user findings.

### Microsoft Unauthorized Device

Remove this row from `packet_ac_l2_3_1_1_microsoft/authorized_devices.csv`:

```csv
Contracts-CUI,dev-001
```

Expected result: `NOT MET`; device authorization-policy mismatch.

### Okta/Box/Jamf Unauthorized User

Append a collaboration entry in `box_collaborations.json` granting
`00u9guest` access to `CUI-Contracts-Box-Folder`.

Expected result: `NOT MET`; guest/external user and unauthorized user findings,
with a candidate Box collaboration removal action.

### Okta/Box/Jamf Unauthorized Device

Add an event in `access_events.json` where `00u1alice` accesses
`CUI-Contracts-Box-Folder` from `jamf-199`.

Expected result: `NOT MET`; unmanaged, non-compliant, and unauthorized device
findings, with a candidate Jamf investigation/update action.

## Project Structure

```text
CMMC/
├── ac_l1_b_1_i_verifier.py                    # Core verifier and adapters
├── streamlit_demo_dashboard.py                # Main Streamlit v2 demo
├── generate_remediation_with_openai.py        # OpenAI remediation generator
├── packet_ac_l2_3_1_1_microsoft/              # Microsoft CSV evidence packet
├── packet_ac_l2_3_1_1_okta_box_jamf/          # Okta/Box/Jamf JSON evidence packet
└── packet_ac_l1_b_1_i/                        # Original Level 1 packet
```

## Positioning Notes

The demo should be described as one Level 2 control in depth, not full Level 2
coverage. The roadmap table shows how the same adapter plus objective-test
pattern extends to additional controls without claiming they are implemented.
