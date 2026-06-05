# Control Configuration: AC.L2-3.1.1

## Control Metadata
- control_id: AC.L2-3.1.1
- control_name: Authorized Access Control
- requirement: Limit system access to authorized users, processes acting on behalf of authorized users, and devices.
- assessment_scope_v2: Authorized users, processes, and devices access to CUI.

## CUI Scope
- cui_resource_name: CUI-Contracts-Box-Folder
- cui_resource_description: Box folder used for controlled contract deliverables containing CUI.

## Identity and Authorization Source
- identity_source: Okta
- authorized_group_name: CUI-Authorized
- authorized_group_description: Users approved by compliance and the system owner to access CUI.

## Demo Policy Rules
1. Only members of `CUI-Authorized` may access `CUI-Contracts-Box-Folder`.
2. Users with effective access must have active identity status.
3. External identities are prohibited for CUI access (`user_type` must be `Member`; `Guest` not allowed).
4. Box collaborations granted to groups must be expanded to individual Okta users for effective access evaluation.
5. Only managed and compliant Jamf devices listed in `authorization_policy.json` may access `CUI-Contracts-Box-Folder`.
6. Only enabled Okta applications listed in `authorization_policy.json` may access `CUI-Contracts-Box-Folder`.

## Evidence Files
- okta_users.json
- okta_groups.json
- box_collaborations.json
- jamf_devices.json
- authorization_policy.json
- okta_apps.json
- access_events.json

## Notes
- This packet is intentionally constructed as a clean baseline expected to evaluate to MET.
- The raw export shape is intentionally different from the Microsoft CSV packet to demonstrate real normalization.
