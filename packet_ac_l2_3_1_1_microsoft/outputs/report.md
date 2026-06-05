# AC.L2-3.1.1 Assessment Report (MET)

## What Was Assessed
- Control: `AC.L2-3.1.1` on CUI resource `Contracts-CUI`.
- Source stack: `Microsoft Entra + SharePoint + Intune`.
- Authorized group baseline: `CUI-Authorized`.
- Effective users evaluated: `6`.

## Normalization Summary
- `raw_format`: `CSV exports modeled after Microsoft admin center exports`
- `users`: `7`
- `groups`: `4`
- `permissions`: `3`
- `devices`: `4`
- `processes`: `2`
- `access_events`: `4`
- `resource_permission_edges`: `2`

## Runtime Metrics
- `verification_elapsed_ms`: `0.92`
- `users_evaluated`: `7`
- `devices_evaluated`: `4`
- `processes_evaluated`: `2`
- `permission_edges_evaluated`: `2`
- `access_events_evaluated`: `4`
- `findings_found`: `0`

## Rules Applied
- 1. Only members of `CUI-Authorized` may access `Contracts-CUI`.
- 2. Users with effective access must have `account_enabled = true`.
- 3. External identities are prohibited for CUI access (`user_type` must be `Member`; `Guest` not allowed).
- 4. SharePoint permissions granted to groups must be expanded to individual users for effective access evaluation.
- 5. Only Intune-managed and compliant devices in `authorized_devices.csv` may access `Contracts-CUI`.
- 6. Only enabled service principals listed in `authorized_processes.csv` may access `Contracts-CUI`.

## Evidence Used
- `control_doc.md`
- `entra_users.csv`
- `entra_groups.csv`
- `entra_group_members.csv`
- `sharepoint_site_permissions.csv`
- `intune_devices.csv`
- `authorized_devices.csv`
- `entra_service_principals.csv`
- `authorized_processes.csv`
- `fci_access_events.csv`

## Assessment Objectives
- `a_authorized_users_identified`: `MET`
- `b_authorized_processes_identified`: `MET`
- `c_authorized_devices_identified`: `MET`
- `d_access_limited_to_authorized_users`: `MET`
- `e_access_limited_to_authorized_processes`: `MET`
- `f_access_limited_to_authorized_devices`: `MET`

## Findings
- No findings. Effective access satisfied the configured rules.

## Recommended Remediation
- None required for current result.
