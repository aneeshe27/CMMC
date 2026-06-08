# Control Configuration: AC.L2-3.1.1

## Control Metadata
- control_id: AC.L2-3.1.1
- control_name: Authorized Access Control
- requirement: Limit system access to authorized users, processes acting on behalf of authorized users, and devices.
- assessment_scope_v2: Authorized users, processes, and devices access to CUI.

## CUI Scope
- cui_resource_name: Contracts-CUI
- cui_resource_description: SharePoint Online site used for controlled contract deliverables containing CUI.

## Identity and Authorization Source
- identity_source: Microsoft Entra ID
- authorized_group_name: CUI-Authorized
- authorized_group_description: Users approved by compliance and the system owner to access CUI.

## Demo Policy Rules
1. Only members of `CUI-Authorized` may access `Contracts-CUI`.
2. Users with effective access must have `account_enabled = true`.
3. External identities are prohibited for CUI access (`user_type` must be `Member`; `Guest` not allowed).
4. SharePoint permissions granted to groups must be expanded to individual users for effective access evaluation.
5. Only Intune-managed and compliant devices in `authorized_devices.csv` may access `Contracts-CUI`.
6. Only enabled service principals listed in `authorized_processes.csv` may access `Contracts-CUI`.

## Evidence Files
- entra_users.csv
- entra_groups.csv
- entra_group_members.csv
- sharepoint_site_permissions.csv
- intune_devices.csv
- authorized_devices.csv
- entra_service_principals.csv
- authorized_processes.csv
- cui_access_events.csv

## Notes
- This packet is intentionally constructed as a clean baseline expected to evaluate to MET.
- A demo failure can be introduced by adding a direct SharePoint user permission for the external guest user.
