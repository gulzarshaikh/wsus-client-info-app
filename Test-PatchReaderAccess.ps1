#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies that the patch lookup service account can read every GPO in a domain
    (AD object, permissions and SYSVOL), by running the checks AS that account.
    Also proves Start-Job -Credential works on this server for that account.
.EXAMPLE
    .\Test-PatchReaderAccess.ps1 -Domain domainA.fqdn
    (prompts for domainA\svc-patchlookup and its password)
#>
param(
    [Parameter(Mandatory)][string]$Domain,
    [pscredential]$Credential = (Get-Credential -Message "Service account for $Domain (DOMAIN\svc-patchlookup)")
)

$check = {
    param($Domain)
    Import-Module GroupPolicy -ErrorAction Stop
    $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    foreach ($gpo in Get-GPO -All -Domain $Domain -Server $Domain) {
        $id = "{$($gpo.Id)}"
        $r  = [ordered]@{ Gpo = $gpo.DisplayName; RunAs = $who; AdRead = 'OK'; PermRead = 'OK'; SysvolRead = 'OK'; Error = '' }
        try { $null = Get-GPPermission -Guid $gpo.Id -All -Domain $Domain -Server $Domain -ErrorAction Stop }
        catch { $r.PermRead = 'FAIL'; $r.Error += "Perm: $($_.Exception.Message) " }
        try { $null = Get-Content "\\$Domain\SYSVOL\$Domain\Policies\$id\gpt.ini" -ErrorAction Stop }
        catch { $r.SysvolRead = 'FAIL'; $r.Error += "SYSVOL: $($_.Exception.Message)" }
        [pscustomobject]$r
    }
}

try {
    # Start-Job -Credential creates a fresh logon, so new group membership is picked up
    $job = Start-Job -ScriptBlock $check -ArgumentList $Domain -Credential $Credential
    $results = $job | Wait-Job | Receive-Job -ErrorAction Stop
    $job | Remove-Job
} catch {
    Write-Error "Could not run as $($Credential.UserName): $($_.Exception.Message)"
    Write-Host 'Check LogonWorkstations on the account and logon rights on this server.' -ForegroundColor Yellow
    exit 1
}

# Note: GPOs the account cannot read at all will not be returned by Get-GPO -All.
# Compare the count with the same query run as an admin.
$adminCount = (Get-GPO -All -Domain $Domain -Server $Domain).Count
$fails = $results | Where-Object { $_.PermRead -eq 'FAIL' -or $_.SysvolRead -eq 'FAIL' }

Write-Host "`nRan as      : $($results[0].RunAs)"
Write-Host "GPOs (admin): $adminCount"
Write-Host "GPOs (svc)  : $($results.Count)"
Write-Host "Failures    : $(@($fails).Count)"
if ($results.Count -lt $adminCount) {
    Write-Warning 'The service account sees fewer GPOs than you. Missing GPOs:'
    $seen = $results.Gpo
    Get-GPO -All -Domain $Domain -Server $Domain | Where-Object { $seen -notcontains $_.DisplayName } |
        ForEach-Object { "  - $($_.DisplayName)" }
}
if ($fails) { $fails | Format-Table Gpo, PermRead, SysvolRead, Error -AutoSize -Wrap }
if ($results.Count -eq $adminCount -and -not $fails) {
    Write-Host 'PASS: service account can read all GPOs.' -ForegroundColor Green
}
