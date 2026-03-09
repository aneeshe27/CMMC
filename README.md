# CMMC L1 Demo Agent

A deterministic verifier and demo agent for **CMMC Level 1** control **AC.L1-B.1.I** (Authorized Access Control). Evaluates whether only authorized users, processes, and devices have effective access to FCI (Federal Contract Information) in SharePoint Online.

## Overview

This project provides:

- **Deterministic verification** — Explainable checks against evidence packets (CSV exports from Microsoft Entra ID, SharePoint, Intune)
- **Streamlit demo** — Interactive UI to run verification and view results
- **AI-powered remediation** — Optional OpenAI integration to generate remediation steps from verification findings

## Control in Scope

| Field | Value |
|-------|-------|
| Control ID | AC.L1-B.1.I |
| Control Name | Authorized Access Control |
| Requirement | Limit system access to authorized users, processes, and devices |
| Scope | Authorized users, processes, and devices access to FCI in SharePoint Online |

## Quick Start

### Prerequisites

- Python 3.10+
- [Streamlit](https://streamlit.io/) (for the demo app)

### Install Dependencies

```bash
pip install streamlit
```

### Run the Streamlit Demo

```bash
streamlit run streamlit_demo_ac_l1_b_1_i.py
```

### Run Verification from CLI

```python
from ac_l1_b_1_i_verifier import verify_packet, write_outputs

result = verify_packet("packet_ac_l1_b_1_i")
write_outputs("packet_ac_l1_b_1_i", result)
```

### Generate Remediation (Optional)

Requires an OpenAI API key. Set `OPENAI_API_KEY` in your environment.

```bash
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
| `intune_devices.csv` | Intune-managed devices |
| `authorized_devices.csv` | Approved device list |
| `entra_service_principals.csv` | App/process identities |
| `authorized_processes.csv` | Allowed process list |
| `fci_access_events.csv` | Access events (users, apps, devices) |

Outputs are written to `<packet>/outputs/`:
- `report.md` — Human-readable verification report
- `scorecard.json` — Structured results
- `remediation_steps.md` — Generated remediation (when using OpenAI)

## Project Structure

```
CMMC/
├── ac_l1_b_1_i_verifier.py      # Core verification logic
├── streamlit_demo_ac_l1_b_1_i.py # Streamlit demo app
├── generate_remediation_with_openai.py  # OpenAI remediation generator
├── packet_ac_l1_b_1_i/          # Sample evidence packet
│   ├── control_doc.md
│   ├── *.csv
│   └── outputs/
└── README.md
```

## License

MIT
