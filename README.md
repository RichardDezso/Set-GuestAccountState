# Set-GuestAccountState

A PowerShell script to securely manage the built-in Guest account on Windows 10 and 11.  
By default, it disables the Guest account (recommended) and can optionally ensure it is not part of the local Administrators group.  

## Features
- Enable or disable the Guest account (default: Disabled for security)
- Optionally remove Guest from the local Administrators group
- Audit-only mode to report current state without changes
- Works even if Guest is renamed or localized (resolved by SID)
- Supports `-WhatIf` and `-Confirm` for safe testing

## Requirements
- Windows 10, Windows 11, or Windows Server (2016, 2019, 2022)  
- PowerShell 5.1 (default inbox version)  
- Run as **Administrator**

## Usage
```powershell
# Disable Guest and remove from Administrators (recommended)
.\Set-GuestAccountState.ps1 -Ensure Disabled -AlsoRemoveFromAdministrators

# Just disable Guest
.\Set-GuestAccountState.ps1 -Ensure Disabled

# Enable Guest (not recommended)
.\Set-GuestAccountState.ps1 -Ensure Enabled

# Audit only (no changes)
.\Set-GuestAccountState.ps1 -AuditOnly
