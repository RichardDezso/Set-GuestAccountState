<#
.SYNOPSIS
  Enable or disable the built-in Guest account safely (with optional admin-group cleanup).

.DESCRIPTION
  Resolves the Guest account by SID (RID 501) so it works even if renamed/localized.
  Supports -WhatIf/-Confirm, audit-only, and optional removal from the local Administrators group.

.PARAMETER Ensure
  'Disabled' (default) to disable Guest; 'Enabled' to enable Guest.

.PARAMETER AlsoRemoveFromAdministrators
  When set, ensures Guest is NOT a member of the local Administrators group.

.PARAMETER AuditOnly
  Report current Guest state and membership; do not change anything.

.EXAMPLE
  # Secure default: disable Guest and remove it from Administrators
  .\Set-GuestAccountState.ps1 -Ensure Disabled -AlsoRemoveFromAdministrators

.EXAMPLE
  # Just report current state
  .\Set-GuestAccountState.ps1 -AuditOnly

.NOTES
  Run as Administrator.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [ValidateSet('Disabled','Enabled')]
  [string]$Ensure = 'Disabled',

  [switch]$AlsoRemoveFromAdministrators,

  [switch]$AuditOnly
)

function Test-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Access denied. Please run PowerShell as Administrator."
  }
}

function Ensure-LocalAccountsModule {
  if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
    throw "The 'Microsoft.PowerShell.LocalAccounts' module is required on this host."
  }
}

# Resolve built-in Administrators group name via well-known SID S-1-5-32-544 (handles localization)
function Get-AdministratorsGroupName {
  try {
    $sid = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-32-544"
    return ($sid.Translate([System.Security.Principal.NTAccount])).Value.Split('\')[-1]
  } catch {
    return "Administrators"
  }
}

# Get Guest local user by RID 501 (works if renamed)
function Get-GuestLocalUser {
  $guest = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match '-501$' }
  if (-not $guest) {
    throw "Guest account not found on this system."
  }
  return $guest
}

# Remove Guest from Administrators if present (compare by SID for reliability)
function Ensure-GuestNotInAdmins([string]$adminsGroup, [System.Security.Principal.SecurityIdentifier]$guestSid) {
  $member = Get-LocalGroupMember -Group $adminsGroup -ErrorAction SilentlyContinue |
            Where-Object { $_.SID -and $_.SID.Value -eq $guestSid.Value }
  if ($member) {
    if ($PSCmdlet.ShouldProcess("Guest ($($guestSid.Value))", "Remove from local group '$adminsGroup'")) {
      Remove-LocalGroupMember -Group $adminsGroup -Member $guestSid.Value -ErrorAction Stop
      Write-Host "Removed Guest from '$adminsGroup'."
    }
  } else {
    Write-Host "Guest is not a member of '$adminsGroup'."
  }
}

# ---------------- Main ----------------
Test-Admin
Ensure-LocalAccountsModule

$adminsGroup = Get-AdministratorsGroupName
$guest = Get-GuestLocalUser

Write-Host "Guest account resolved as: $($guest.Name)  (SID: $($guest.SID.Value))"
Write-Host "Current state: " -NoNewline
Write-Host ($guest.Enabled ? "Enabled" : "Disabled")

# Audit-only path
if ($AuditOnly) {
  $isInAdmins = [bool](Get-LocalGroupMember -Group $adminsGroup -ErrorAction SilentlyContinue |
                        Where-Object { $_.SID -and $_.SID.Value -eq $guest.SID.Value })
  Write-Host "Member of '$adminsGroup': $isInAdmins"
  return
}

# Enforce account state
try {
  switch ($Ensure) {
    'Disabled' {
      if ($guest.Enabled) {
        if ($PSCmdlet.ShouldProcess($guest.Name, "Disable local user")) {
          Disable-LocalUser -Name $guest.Name -ErrorAction Stop
          Write-Host "Guest account disabled."
        }
      } else {
        Write-Host "No change: Guest is already disabled."
      }
    }
    'Enabled' {
      if (-not $guest.Enabled) {
        if ($PSCmdlet.ShouldProcess($guest.Name, "Enable local user")) {
          Enable-LocalUser -Name $guest.Name -ErrorAction Stop
          Write-Host "Guest account enabled."
        }
      } else {
        Write-Host "No change: Guest is already enabled."
      }
    }
  }
} catch {
  Write-Error "Failed to set Guest state to '$Ensure': $($_.Exception.Message)"
  exit 1
}

# Optional: remove from local Administrators
if ($AlsoRemoveFromAdministrators) {
  try {
    Ensure-GuestNotInAdmins -adminsGroup $adminsGroup -guestSid $guest.SID
  } catch {
    Write-Error "Failed while updating '$adminsGroup' membership: $($_.Exception.Message)"
    exit 1
  }
}
