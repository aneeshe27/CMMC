## Why It Failed  
The control AC.L1-B.1.I failed because an unauthorized external user, **grace.partner_external#EXT#@contoso-demo.onmicrosoft.com**, has effective access to the SharePoint site **Contracts-FCI** without membership in the approved Entra group **FCI-Authorized**. This violates the access restriction requirement that only authorized users have permissions to Controlled Unclassified Information (FCI) repositories.

## Remediation Steps (Prioritized)  
1. **Remove Unauthorized User Access**  
   - Immediately remove **grace.partner_external#EXT#@contoso-demo.onmicrosoft.com** from all permissions on the **Contracts-FCI** SharePoint site.

2. **Enforce Group-Based Access Control**  
   - Configure SharePoint permissions so that only members of the Entra group **FCI-Authorized** have access to **Contracts-FCI**.
   - Audit all site permissions to identify and remove any users/accounts not in **FCI-Authorized**.

3. **Validate and Restrict Guest/External Access**  
   - Review external sharing policies for **Contracts-FCI** to ensure guests are explicitly approved and added only via the **FCI-Authorized** group.
   - Remove or restrict access for any external accounts not verified or approved.

4. **Manage Account Lifecycle**  
   - Disable or remove inactive or unnecessary accounts from both Entra and SharePoint site permissions to reduce risk of unauthorized access.

5. **Apply Device Compliance Controls**  
   - Enforce conditional access requiring connecting devices to be Intune-managed and compliant before accessing FCI data.

6. **Harden Permission Assignments**  
   - Regularly schedule permission reviews and audits to prevent drift.
   - Limit direct user assignments by relying strictly on group-based permissions.

## Quick Validation Checklist  
- [ ] Verify no user outside of **FCI-Authorized** has permissions on **Contracts-FCI** SharePoint site.  
- [ ] Confirm **grace.partner_external#EXT#@contoso-demo.onmicrosoft.com** is removed from site permissions.  
- [ ] Check SharePoint external sharing settings restrict guest access consistent with policy.  
- [ ] Ensure all active site users belong to the Entra group **FCI-Authorized**.  
- [ ] Validate Intune compliance gating for device access to SharePoint site.  
- [ ] Schedule periodic access and group membership reviews documented for audit purposes.
