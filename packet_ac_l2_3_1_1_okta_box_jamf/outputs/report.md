# AC.L2-3.1.1 Assessment Report (MET)

## What Was Assessed
- Control: `AC.L2-3.1.1` on CUI resource `CUI-Contracts-Box-Folder`.
- Source stack: `Okta + Box + Jamf`.
- Authorized group baseline: `CUI-Authorized`.
- Effective users evaluated: `3`.

## Normalization Summary
- `raw_format`: `API-style JSON: nested Okta profiles/groups, Box collaboration objects, and Jamf device extension attributes`
- `users`: `4`
- `groups`: `2`
- `permissions`: `3`
- `devices`: `3`
- `processes`: `2`
- `access_events`: `4`
- `resource_permission_edges`: `2`

## Runtime Metrics
- `verification_elapsed_ms`: `0.5`
- `users_evaluated`: `4`
- `devices_evaluated`: `3`
- `processes_evaluated`: `2`
- `permission_edges_evaluated`: `2`
- `access_events_evaluated`: `4`
- `findings_found`: `0`

## Rules Applied
- 1. Only members of `CUI-Authorized` may access `CUI-Contracts-Box-Folder`.
- 2. Users with effective access must have active identity status.
- 3. External identities are prohibited for CUI access (`user_type` must be `Member`; `Guest` not allowed).
- 4. Box collaborations granted to groups must be expanded to individual Okta users for effective access evaluation.
- 5. Only managed and compliant Jamf devices listed in `authorization_policy.json` may access `CUI-Contracts-Box-Folder`.
- 6. Only enabled Okta applications listed in `authorization_policy.json` may access `CUI-Contracts-Box-Folder`.

## Evidence Used
- `control_doc.md`
- `okta_users.json`
- `okta_groups.json`
- `box_collaborations.json`
- `jamf_devices.json`
- `authorization_policy.json`
- `okta_apps.json`
- `access_events.json`

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
