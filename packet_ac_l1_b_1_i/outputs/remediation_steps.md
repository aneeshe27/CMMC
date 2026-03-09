## Why It Failed

The control AC.L1-B.1.I failed because an unmanaged and non-compliant device identified as 'UNMANAGED-CONTRACTOR' accessed the controlled SharePoint site `Contracts-FCI`. This violates the requirement to limit access to authorized devices only. The device was neither enrolled in Intune nor listed in the authorized devices inventory, allowing unauthorized access to Controlled Federal Information (FCI).

## Remediation Steps (Prioritized)

1. **Enforce Device Compliance via Entra Conditional Access**  
   Configure conditional access policies requiring Intune-managed and compliant devices to access the `Contracts-FCI` SharePoint site.

2. **Remove Unauthorized Device Access**  
   Remove permissions or block access tokens linked to the device 'UNMANAGED-CONTRACTOR' in SharePoint site permissions.

3. **Restrict SharePoint Site Permissions to Authorized Entra Group**  
   Ensure that only members of the Entra group `FCI-Authorized` have SharePoint access to `Contracts-FCI`.

4. **Validate and Update Authorized Devices Inventory**  
   Regularly update `authorized_devices.csv` and enforce device registration and compliance checks.

5. **Disable or Remove Access for Inactive or External Accounts**  
   Audit users with access to `Contracts-FCI`, disabling accounts not active or not in compliance.

## Quick Validation Checklist

- [ ] Confirm conditional access policies enforce Intune-compliance on `Contracts-FCI` access.  
- [ ] Verify removal of 'UNMANAGED-CONTRACTOR' from SharePoint `Contracts-FCI` permissions.  
- [ ] Confirm `Contracts-FCI` permissions limited to members of `FCI-Authorized` group only.  
- [ ] Validate all accessing devices are listed in `authorized_devices.csv` and enrolled in Intune as compliant.  
- [ ] Review and disable inactive or unauthorized user accounts in Entra.
