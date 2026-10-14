#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Resolves WSUS / Windows Update patching settings for a computer from GPO only.
.EXAMPLE
    .\Get-PatchInfo.ps1 -ComputerName SRV01
    .\Get-PatchInfo.ps1 -ComputerName SRV01 -Domains 'forest1.local','forest2.local'
#>
param(
    [Parameter(Mandatory)][string]$ComputerName,
    # One entry per forest/domain to search. Edit the defaults for your estate.
    [string[]]$Domains = @('forest1.example.com', 'forest2.example.com')
)
$ErrorActionPreference = 'Stop'

# ---------- Input validation (this will be called from a web app) ----------
if ($ComputerName -notmatch '^[A-Za-z0-9-]{1,15}$') {
    @{ error = 'Invalid computer name. Use the NetBIOS host name (max 15 chars).' } | ConvertTo-Json
    exit 1
}

$WuKey = 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate'
$AuKey = "$WuKey\AU"

function ConvertTo-LdapSafe([string]$s) {
    # RFC 4515 escaping for values used inside an LDAP filter
    $s -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
}

# ---------- 1. Find the computer in one of the forests ----------
$computer = $null; $domain = $null
foreach ($d in $Domains) {
    $c = Get-ADComputer -Filter "Name -eq '$ComputerName'" -Server $d `
         -Properties operatingSystem, operatingSystemVersion, primaryGroupID -ErrorAction SilentlyContinue
    if ($c) { $computer = $c; $domain = $d; break }
}
if (-not $computer) {
    @{ error = "Computer '$ComputerName' not found in: $($Domains -join ', ')" } | ConvertTo-Json
    exit 1
}
$parentDn = $computer.DistinguishedName -replace '^CN=(?:\\.|[^,])+,', ''
$isDC     = ($computer.primaryGroupID -eq 516)

# ---------- 2. Build the computer's SID set for security filtering ----------
$domainSid = $computer.SID.AccountDomainSid.Value
$sids = [System.Collections.Generic.HashSet[string]]::new()
[void]$sids.Add($computer.SID.Value)
[void]$sids.Add('S-1-1-0')                                      # Everyone
[void]$sids.Add('S-1-5-11')                                     # Authenticated Users
[void]$sids.Add("$domainSid-$($computer.primaryGroupID)")       # Primary group (Domain Computers / Domain Controllers)
if ($isDC) { [void]$sids.Add('S-1-5-9') }                       # Enterprise Domain Controllers
$dnFilter = ConvertTo-LdapSafe $computer.DistinguishedName
Get-ADGroup -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$dnFilter)" -Server $domain |
    ForEach-Object { [void]$sids.Add($_.SID.Value) }

# ---------- 3. WMI filter helper (best-effort offline guess) ----------
function Get-WmiGuess([string]$query) {
    if (-not $query) { return 'None' }
    if ($query -match '(?i)\bor\b') { return 'Unknown' }        # Too complex to guess safely
    $verAd = if ($computer.operatingSystemVersion -match '^(\d+\.\d+)\s*\((\d+)\)') { "$($Matches[1]).$($Matches[2])" }
    $productType = if ($isDC) { 2 } else { 3 }                  # 2 = DC, 3 = member server
    $checked = 0
    foreach ($m in [regex]::Matches($query, "(?i)Version\s+like\s+['""]([^'""]+)['""]")) {
        $checked++
        $prefix = $m.Groups[1].Value.TrimEnd('%')
        if (-not $verAd -or -not $verAd.StartsWith($prefix)) { return 'LikelyFiltered' }
    }
    foreach ($m in [regex]::Matches($query, "(?i)ProductType\s*=\s*['""]?(\d)")) {
        $checked++
        if ([int]$m.Groups[1].Value -ne $productType) { return 'LikelyFiltered' }
    }
    if ($checked -gt 0) { 'LikelyApplies' } else { 'Unknown' }
}

# ---------- 4. Walk GPOs in precedence order ----------
$som = Get-GPInheritance -Target $parentDn -Domain $domain -Server $domain
$gpoResults = @()
$precedence = 0
foreach ($link in $som.InheritedGpoLinks) {
    $precedence++
    $gpo = Get-GPO -Guid $link.GpoId -Domain $domain -Server $domain

    # Security filtering
    $perms   = Get-GPPermission -Guid $link.GpoId -All -Domain $domain -Server $domain
    $matched = $perms | Where-Object { $_.Permission -eq 'GpoApply' -and $_.Trustee.Sid -and $sids.Contains($_.Trustee.Sid.Value) }
    $denied  = $matched | Where-Object Denied
    $allowed = $matched | Where-Object { -not $_.Denied }
    $secStatus = if ($denied) { 'Denied' } elseif ($allowed) { 'Applies' } else { 'Filtered' }

    # WMI filter
    $wmiName = $null; $wmiQuery = $null; $wmiGuess = 'None'
    if ($gpo.WmiFilter) {
        $wmiName  = $gpo.WmiFilter.Name
        $wmiQuery = $gpo.WmiFilter.Query
        if (-not $wmiQuery) {
            # Fallback: read the filter object from AD (msWMI-Parm2 holds the WQL)
            $wo = Get-ADObject -LDAPFilter "(&(objectClass=msWMI-Som)(msWMI-Name=$(ConvertTo-LdapSafe $wmiName)))" `
                  -Server $domain -Properties 'msWMI-Parm2'
            if ($wo) { $wmiQuery = $wo.'msWMI-Parm2' }
        }
        $wmiGuess = Get-WmiGuess $wmiQuery
    }

    $status = switch ($true) {
        ($secStatus -ne 'Applies')         { $secStatus; break }
        ($wmiGuess -eq 'LikelyFiltered')   { 'LikelyFilteredByWmi'; break }
        ($wmiGuess -in 'Unknown', 'LikelyApplies') { 'Conditional'; break }
        default                            { 'Applies' }
    }

    # Windows Update registry policy values in this GPO
    $settings = @()
    foreach ($key in $WuKey, $AuKey) {
        $settings += Get-GPRegistryValue -Guid $link.GpoId -Key $key -Domain $domain -Server $domain -ErrorAction SilentlyContinue |
            Where-Object { $_.ValueName } |
            ForEach-Object {
                [pscustomobject]@{ Key = $key; ValueName = $_.ValueName; Value = $_.Value; PolicyState = "$($_.PolicyState)" }
            }
    }

    $gpoResults += [pscustomobject]@{
        Precedence = $precedence; Name = $link.DisplayName; Id = "$($link.GpoId)"
        Enforced = $link.Enforced; Status = $status; SecurityFiltering = $secStatus
        WmiFilter = $wmiName; WmiQuery = $wmiQuery; WmiGuess = $wmiGuess
        HasWuSettings = [bool]$settings; Settings = $settings
    }
}

# ---------- 5. Resolve the winning value per setting ----------
function Resolve-Effective([string[]]$statuses) {
    $result = [ordered]@{}
    foreach ($g in $gpoResults | Where-Object { $_.Status -in $statuses } | Sort-Object Precedence) {
        foreach ($s in $g.Settings) {
            $id = "$($s.Key)\$($s.ValueName)"
            if (-not $result.Contains($id)) {           # First hit = highest precedence wins
                $result[$id] = [pscustomobject]@{
                    ValueName = $s.ValueName
                    Value     = if ($s.PolicyState -eq 'Delete') { $null } else { $s.Value }
                    State     = $s.PolicyState
                    SourceGpo = $g.Name
                }
            }
        }
    }
    $result
}

function Get-Summary($eff) {
    $v = @{}; foreach ($e in $eff.Values) { $v[$e.ValueName] = $e.Value }
    $days = @{ 0 = 'Every day'; 1 = 'Sunday'; 2 = 'Monday'; 3 = 'Tuesday'; 4 = 'Wednesday'; 5 = 'Thursday'; 6 = 'Friday'; 7 = 'Saturday' }
    $au   = @{ 2 = 'Notify for download and install'; 3 = 'Auto download, notify for install'
               4 = 'Auto download and scheduled install'; 5 = 'Local admin chooses' }
    [pscustomobject]@{
        WsusServer    = if ($v['UseWUServer'] -eq 1) { $v['WUServer'] } else { 'Not configured (UseWUServer not set)' }
        TargetGroup   = if ($v['TargetGroupEnabled'] -eq 1) { $v['TargetGroup'] } else { 'Not configured' }
        UpdatesOff    = ($v['NoAutoUpdate'] -eq 1)
        Mode          = if ($null -eq $v['AUOptions']) { 'Not configured' }
                        elseif ($au.ContainsKey([int]$v['AUOptions'])) { $au[[int]$v['AUOptions']] }
                        else { "Unmapped value $($v['AUOptions'])" }
        InstallDay    = if ($v['AUOptions'] -eq 4 -and $null -ne $v['ScheduledInstallDay']) { $days[[int]$v['ScheduledInstallDay']] } else { 'n/a' }
        InstallHour   = if ($v['AUOptions'] -eq 4 -and $null -ne $v['ScheduledInstallTime']) { '{0:00}:00' -f [int]$v['ScheduledInstallTime'] } else { 'n/a' }
        NoRebootWithLoggedOnUsers = ($v['NoAutoRebootWithLoggedOnUsers'] -eq 1)
    }
}

$definite    = Resolve-Effective @('Applies')
$conditional = Resolve-Effective @('Applies', 'Conditional')

[pscustomobject]@{
    Computer   = $computer.Name
    Domain     = $domain
    OU         = $parentDn
    OS         = "$($computer.operatingSystem) $($computer.operatingSystemVersion)"
    IsDC       = $isDC
    InheritanceBlocked = $som.GpoInheritanceBlocked
    Summary    = Get-Summary $definite
    SummaryIfConditionalApply = Get-Summary $conditional
    EffectiveSettings = @($definite.Values)
    EffectiveSettingsIfConditionalApply = @($conditional.Values)
    Gpos       = $gpoResults
    Warnings   = @(
        'Site-linked GPOs are not evaluated.'
        'WMI results are a best-effort guess from AD data.'
        'Local policy and manual registry edits are not visible from GPO.'
    )
    GeneratedAt = (Get-Date).ToString('s')
} | ConvertTo-Json -Depth 6
