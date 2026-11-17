<#
.SYNOPSIS
  Finds risky identities: stale accounts, guests, and users without MFA registered.
.NOTES
  signInActivity needs Entra ID P1. Without it, last sign-in values are empty.
#>
[CmdletBinding()]
param(
    [int]$InactiveDays = 90
)

. (Join-Path $PSScriptRoot '../lib/Common.ps1')
Connect-EntraLab -Scopes 'User.Read.All', 'AuditLog.Read.All', 'Reports.Read.All'

$cutoff = (Get-Date).AddDays(-$InactiveDays)
$props = 'Id', 'DisplayName', 'UserPrincipalName', 'AccountEnabled', 'UserType', 'CreatedDateTime', 'SignInActivity', 'Department'

Write-Host "Fetching users..." -ForegroundColor Cyan
$users = Get-MgUser -All -Property $props

# MFA registration status
$mfa = @{}
try {
    Get-MgReportAuthenticationMethodUserRegistrationDetail -All | ForEach-Object { $mfa[$_.Id] = $_ }
}
catch { Write-Warning "MFA registration report unavailable: $($_.Exception.Message)" }

$results = foreach ($u in $users) {
    $flags = @()
    $last = @($u.SignInActivity.LastSignInDateTime, $u.SignInActivity.LastNonInteractiveSignInDateTime) |
        Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

    if ($u.AccountEnabled) {
        if ($last -and $last -lt $cutoff) { $flags += "Inactive > $InactiveDays days" }
        elseif (-not $last -and $u.CreatedDateTime -lt $cutoff) { $flags += 'Never signed in' }
        if ($mfa.ContainsKey($u.Id) -and -not $mfa[$u.Id].IsMfaRegistered) { $flags += 'No MFA registered' }
    }
    if ($u.UserType -eq 'Guest') { $flags += 'Guest account - confirm business need' }

    [pscustomobject]@{
        DisplayName   = $u.DisplayName
        UPN           = $u.UserPrincipalName
        Enabled       = $u.AccountEnabled
        UserType      = $u.UserType
        Department    = $u.Department
        LastSignIn    = $last
        MfaRegistered = if ($mfa.ContainsKey($u.Id)) { $mfa[$u.Id].IsMfaRegistered } else { 'unknown' }
        Flags         = ($flags -join '; ')
    }
}

$path = Get-ReportPath -Name 'user-audit'
$results | Export-Csv -NoTypeInformation -Path $path

$flagged = @($results | Where-Object Flags)
Write-Host "`nTotal users: $(@($results).Count)   Flagged: $($flagged.Count)" -ForegroundColor Cyan
$flagged | Format-Table DisplayName, UPN, UserType, LastSignIn, Flags -AutoSize -Wrap
Write-Host "Report saved: $path" -ForegroundColor Green
