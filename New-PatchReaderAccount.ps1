#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Creates a least-privilege, read-only account for the WSUS patch lookup app in ONE domain,
    then reports any GPOs that account will not be able to read.
    Run once per forest by a Domain Admin (or delegated account-creation rights) of that domain.
.EXAMPLE
    .\New-PatchReaderAccount.ps1 -Domain domainA.fqdn -Path 'OU=Service Accounts,DC=domainA,DC=fqdn' -LogonWorkstations MGMT01
#>
param(
    [Parameter(Mandatory)][string]$Domain,
    [Parameter(Mandatory)][string]$Path,                  # OU for the account
    [string]$SamAccountName = 'svc-patchlookup',
    [string]$LogonWorkstations                            # Optional: management server NetBIOS name(s), comma-separated
)
$ErrorActionPreference = 'Stop'

# ---------- 1. Generate a long random password (shown once) ----------
Add-Type -AssemblyName System.Web
$plain  = [System.Web.Security.Membership]::GeneratePassword(32, 6)
$secure = ConvertTo-SecureString $plain -AsPlainText -Force

# ---------- 2. Create the account ----------
$params = @{
    Name                 = $SamAccountName
    SamAccountName       = $SamAccountName
    UserPrincipalName    = "$SamAccountName@$Domain"
    Path                 = $Path
    AccountPassword      = $secure
    Enabled              = $true
    PasswordNeverExpires = $true
    CannotChangePassword = $true
    AccountNotDelegated  = $true
    Description          = 'Read-only: WSUS patch lookup app (GPO and AD read). No group memberships.'
    Server               = $Domain
}
if ($LogonWorkstations) { $params.LogonWorkstations = $LogonWorkstations }
New-ADUser @params
Write-Host "Created $Domain\$SamAccountName" -ForegroundColor Green

# ---------- 3. Report GPOs the account cannot read ----------
# Authenticated Users (S-1-5-11) has Read on GPOs by default. Flag any GPO where it is missing
# and the default Domain Users group (domain SID + 513) has no read either.
$domainSid = (Get-ADDomain -Server $Domain).DomainSID.Value
$readers   = @('S-1-5-11', "$domainSid-513")
$unreadable = foreach ($gpo in Get-GPO -All -Domain $Domain -Server $Domain) {
    $ok = Get-GPPermission -Guid $gpo.Id -All -Domain $Domain -Server $Domain |
          Where-Object { $_.Trustee.Sid -and $readers -contains $_.Trustee.Sid.Value -and -not $_.Denied }
    if (-not $ok) { $gpo.DisplayName }
}
if ($unreadable) {
    Write-Warning "These GPOs may not be readable by $SamAccountName (Authenticated Users removed):"
    $unreadable | ForEach-Object { "  - $_" }
    Write-Host "Fix: add a 'GPO-Readers' group containing $SamAccountName with Read (not Apply) on these GPOs."
} else {
    Write-Host 'All GPOs are readable via Authenticated Users. No extra rights needed.' -ForegroundColor Green
}

# ---------- 4. Show the password once ----------
Write-Host "`nPassword (enter it in Add-Forest.ps1, then discard):" -ForegroundColor Yellow
Write-Host $plain
