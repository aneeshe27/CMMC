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

## Demo Inject Examples (to force `NOT MET`)

- Unauthorized user access:
  - Add direct user permission in `sharepoint_site_permissions.csv` for a user not in `FCI-Authorized`
- Guest/external user access:
  - Add direct permission for user `08f4db5b-3f87-4ce8-b41e-e3268fe55707` on `Contracts-FCI`
- Unauthorized/disabled app event:
  - Add `Contracts-FCI,App,spn-002,...` event row in `fci_access_events.csv`
- Unauthorized/unmanaged/non-compliant device event:
  - Add `Contracts-FCI,...,device_id=dev-099,...` event row in `fci_access_events.csv`

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
