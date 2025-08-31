# Set-GuestAccountState
A PowerShell script to securely manage the built-in Guest account on Windows.  
It can enable or disable the Guest account, optionally ensure it is not part of the local Administrators group, and supports audit-only reporting.

## Features
- Enable or disable the Guest account (default: Disabled for security)
- Optionally remove Guest from the local Administrators group
- Audit-only mode to check status without making changes
- Works even if Guest has been renamed (resolved by SID)
- Supports `-WhatIf` and `-Confirm` for safe testing

## Requirements
- Windows 10 / Windows Server 2016+  
- Run as **Administrator**

## Usage
```powershell
# Disable Guest and remove from Administrators (recommended secure baseline)
.\Set-GuestAccountState.ps1 -Ensure Disabled -AlsoRemoveFromAdministrators

# Just disable Guest
.\Set-GuestAccountState.ps1 -Ensure Disabled

# Check state only (no changes)
.\Set-GuestAccountState.ps1 -AuditOnly

# Safety check with WhatIf
.\Set-GuestAccountState.ps1 -Ensure Disabled -WhatIf


⚠️ Note: Disabling the Guest account is a common security best practice. Test in a non-production environment before applying broadly.
