# CMMC L1 Demo Agent

A deterministic verifier and demo agent for **CMMC Level 1** control **AC.L1-B.1.I** (Authorized Access Control). It evaluates whether only authorized users, processes, and devices have effective access to FCI (Federal Contract Information) in SharePoint Online.

## Overview

This project provides:

- **Deterministic verification**: Explainable checks using evidence packet files (Entra, SharePoint, Intune-style CSV exports)
- **Assessment-objective mapping**: Objective-level status for AC.L1-B.1.I / NIST SP 800-171A objectives `[a]-[f]`
- **Streamlit demo app**: End-to-end verification UI with evidence preview, findings, and output downloads
- **LLM remediation integration**: On `NOT MET`, Streamlit can call OpenAI to generate `remediation_steps.md`

## Control in Scope

| Field | Value |
|-------|-------|
| Control ID | AC.L1-B.1.I |
| Control Name | Authorized Access Control |
| Requirement | Limit system access to authorized users, processes, and devices |
| Implemented Demo Scope | Authorized users, processes, and devices access to FCI in SharePoint Online |

## Quick Start

### Prerequisites

- Python 3.10+
- [Streamlit](https://streamlit.io/) (for the UI)
- Optional: `OPENAI_API_KEY` (if you want LLM remediation generation)

### Install Dependencies

```bash
pip install streamlit
```

### Run the Streamlit Demo

```bash
streamlit run streamlit_demo_ac_l1_b_1_i.py
```

In the app:
- Enter/select packet folder (default: `packet_ac_l1_b_1_i`)
- Click **Verify AC.L1-B.1.I**
- Review status, findings, objective statuses, and generated outputs
- If result is `NOT MET`, the app attempts LLM remediation generation and shows:
  `waiting for llm remediation_steps`

### Run Verification from CLI

```python
from ac_l1_b_1_i_verifier import verify_packet, write_outputs

result = verify_packet("packet_ac_l1_b_1_i")
write_outputs("packet_ac_l1_b_1_i", result)
```

### Generate Remediation (Optional)

Requires an OpenAI API key in the environment:

```bash
export OPENAI_API_KEY="your_key_here"
python generate_remediation_with_openai.py --packet-dir packet_ac_l1_b_1_i
```

## Evidence Packet Structure

Each evidence packet folder (e.g. `packet_ac_l1_b_1_i/`) contains:

| File | Description |
|------|-------------|
| `control_doc.md` | Policy and scope (FCI site, authorized group, rules) |
| `entra_users.csv` | User inventory (enabled/disabled, Member/Guest) |
| `entra_groups.csv` | Group catalog |
| `entra_group_members.csv` | Group membership mapping |
| `sharepoint_site_permissions.csv` | SharePoint site access (users and groups) |
| `intune_devices.csv` | Device posture inventory (managed/compliant) |
| `authorized_devices.csv` | Approved device list per site |
| `entra_service_principals.csv` | App/process identities |
| `authorized_processes.csv` | Allowed process list per site |
| `fci_access_events.csv` | Access events linking users/apps/devices to site actions |

Outputs are written to `<packet>/outputs/`:
- `report.md` — Human-readable verification report
- `scorecard.json` — Structured results
- `remediation_steps.md` — Generated remediation (when using OpenAI)

## What The Verifier Checks

### Core checks (always evaluated)
- Identifies effective user access to the FCI SharePoint site from `sharepoint_site_permissions.csv`
- Expands group-based SharePoint permissions using `entra_group_members.csv`
- Verifies each effective user:
  - exists in `entra_users.csv`
  - has `account_enabled=true`
  - is `Member` if guests are disallowed by policy
  - is in the authorized group from `control_doc.md` (resolved via `entra_groups.csv`)

### Extended checks (evaluated when optional files are present)
- Process/app checks using `entra_service_principals.csv` + `authorized_processes.csv` + `fci_access_events.csv`
- Device checks using `intune_devices.csv` + `authorized_devices.csv` + `fci_access_events.csv`
- Access-event consistency checks for user/app/device activity against allowed scope

### Objective mapping
The report context includes status for AC.L1-B.1.I assessment objectives:
- `[a]` authorized users identified
- `[b]` authorized processes identified
- `[c]` authorized devices identified
- `[d]` access limited to authorized users
- `[e]` access limited to authorized processes
- `[f]` access limited to authorized devices

If optional process/device files are not present, related objectives are marked `NOT ASSESSED` rather than failing by default.

## Status Logic

- `MET`: no findings
- `NOT MET`: one or more findings
- `NOT APPLICABLE`: no SharePoint permissions were found for the configured FCI site


## Objective-Based Injects (A-F)

Use one inject at a time for a clear demo narrative. These are expected to return `NOT MET`.

### [a] Authorized users are identified
- File: `packet_ac_l1_b_1_i/sharepoint_site_permissions.csv`
- Inject row:
  - `Contracts-FCI,User,user-unknown-001,Read`
- Expected failure reason:
  - Effective user is not found in `entra_users.csv`.

### [b] Processes acting on behalf of authorized users are identified
- File: `packet_ac_l1_b_1_i/authorized_processes.csv`
- Inject/corruption:
  - Remove `Contracts-FCI,spn-001` (leave header only).
- Expected failure reason:
  - No authorized process list remains for `Contracts-FCI`.

### [c] Authorized devices are identified
- File: `packet_ac_l1_b_1_i/authorized_devices.csv`
- Inject/corruption:
  - Remove all `Contracts-FCI,...` rows (leave header only).
- Expected failure reason:
  - No authorized device set remains for `Contracts-FCI`.

### [d] Access limited to authorized users
- File: `packet_ac_l1_b_1_i/sharepoint_site_permissions.csv`
- Inject row:
  - `Contracts-FCI,User,08f4db5b-3f87-4ce8-b41e-e3268fe55707,Read`
- Expected failure reason:
  - User is `Guest` and not in `FCI-Authorized`.

### [e] Access limited to authorized processes
- File: `packet_ac_l1_b_1_i/fci_access_events.csv`
- Inject row:
  - `2026-03-03T10:05:00Z,Contracts-FCI,App,spn-002,dev-010,Sync`
- Expected failure reason:
  - `spn-002` is disabled and not in `authorized_processes.csv`.

### [f] Access limited to authorized devices
- File: `packet_ac_l1_b_1_i/fci_access_events.csv`
- Inject row:
  - `2026-03-03T10:06:00Z,Contracts-FCI,User,3f8a9a61-09fd-4d7b-8f4e-7d2d8e6cc101,dev-099,Read`
- Expected failure reason:
  - `dev-099` is unmanaged, non-compliant, and not in `authorized_devices.csv`.



## Project Structure

```text
CMMC/
├── ac_l1_b_1_i_verifier.py               # Core deterministic verification logic
├── streamlit_demo_ac_l1_b_1_i.py         # Streamlit demo app
├── generate_remediation_with_openai.py   # OpenAI remediation generator
├── packet_ac_l1_b_1_i/                   # Sample evidence packet
│   ├── control_doc.md
│   ├── *.csv
│   └── outputs/
└── README.md
```

## License

MIT
