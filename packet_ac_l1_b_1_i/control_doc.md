# Control Configuration: AC.L1-B.1.I

## Control Metadata
- control_id: AC.L1-B.1.I
- control_name: Authorized Access Control
- requirement: Limit system access to authorized users, processes, and devices.
- assessment_scope_v2: Authorized users, processes, and devices access to FCI in SharePoint Online.

## FCI Scope
- fci_site_name: Contracts-FCI
- fci_site_description: SharePoint Online site used for controlled contract deliverables containing FCI.

## Identity and Authorization Source
- identity_source: Microsoft Entra ID
- authorized_group_name: FCI-Authorized
- authorized_group_description: Users approved by compliance and system owner to access FCI.

## Demo Policy Rules
1. Only members of `FCI-Authorized` may access `Contracts-FCI`.
2. Users with effective access must have `account_enabled = true`.
3. External identities are prohibited for FCI access (`user_type` must be `Member`; `Guest` not allowed).
4. SharePoint permissions granted to groups must be expanded to individual users for effective access evaluation.
5. Only Intune-managed and compliant devices in `authorized_devices.csv` may access `Contracts-FCI`.
6. Only enabled service principals listed in `authorized_processes.csv` may access `Contracts-FCI`.

## Evidence Files
- entra_users.csv
- entra_groups.csv
- entra_group_members.csv
- sharepoint_site_permissions.csv
- intune_devices.csv
- authorized_devices.csv
- entra_service_principals.csv
- authorized_processes.csv
- fci_access_events.csv

## Decision Logic
- MET: All users with effective access to `Contracts-FCI` satisfy all policy rules.
- NOT MET: One or more users with effective access violate one or more policy rules.
- NOT APPLICABLE: Control does not apply only if no FCI is stored/processed in scope (not expected for this demo).

## Notes
- This packet is intentionally constructed as a clean baseline expected to evaluate to MET.
- A demo failure can be introduced by adding a direct SharePoint user permission for a non-authorized user.
