<#
.SYNOPSIS
  Secure leaver process: disable, kill sessions, strip groups and directory roles, log everything.
.EXAMPLE
  ./05-Offboard-User.ps1 -UserPrincipalName brian.kamau@contoso.onmicrosoft.com -WhatIf
  ./05-Offboard-User.ps1 -UserPrincipalName brian.kamau@contoso.onmicrosoft.com
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName
)

. (Join-Path $PSScriptRoot '../lib/Common.ps1')
Connect-EntraLab -Scopes 'User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'RoleManagement.ReadWrite.Directory'

$user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" | Select-Object -First 1
if (-not $user) { throw "User $UserPrincipalName not found." }

$log = New-Object System.Collections.Generic.List[object]
function Write-Log($Action, $Target, $Result) {
    $log.Add([pscustomobject]@{ Time = (Get-Date -Format s); User = $UserPrincipalName; Action = $Action; Target = $Target; Result = $Result })
    Write-Host ("  [{0}] {1} {2}" -f $Result, $Action, $Target)
}

# 1. Disable the account first (stops new sign-ins)
if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Disable account')) {
    Update-MgUser -UserId $user.Id -AccountEnabled:$false
    Write-Log 'Disable account' $UserPrincipalName 'OK'
}

# 2. Revoke refresh tokens / sessions
if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Revoke sign-in sessions')) {
    Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
    Write-Log 'Revoke sessions' $UserPrincipalName 'OK'
}

# 3. Remove group memberships and directory roles
$memberOf = Get-MgUserMemberOf -UserId $user.Id -All
foreach ($m in $memberOf) {
    $type = $m.AdditionalProperties['@odata.type']
    $name = $m.AdditionalProperties['displayName']

    if ($type -eq '#microsoft.graph.group') {
        if ($m.AdditionalProperties['groupTypes'] -contains 'DynamicMembership') {
            Write-Log 'Skip dynamic group (membership is rule-based)' $name 'SKIPPED'; continue
        }
        if ($PSCmdlet.ShouldProcess($name, 'Remove from group')) {
            try { Remove-MgGroupMemberByRef -GroupId $m.Id -DirectoryObjectId $user.Id; Write-Log 'Remove from group' $name 'OK' }
            catch { Write-Log 'Remove from group' $name "FAILED: $($_.Exception.Message)" }
        }
    }
    elseif ($type -eq '#microsoft.graph.directoryRole') {
        if ($PSCmdlet.ShouldProcess($name, 'Remove directory role')) {
            try { Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $m.Id -DirectoryObjectId $user.Id; Write-Log 'Remove role' $name 'OK' }
            catch { Write-Log 'Remove role' $name "FAILED: $($_.Exception.Message)" }
        }
    }
}

$path = Get-ReportPath -Name "offboarding-$($UserPrincipalName.Split('@')[0])"
$log | Export-Csv -NoTypeInformation -Path $path
Write-Host "`nOffboarding complete. Evidence log: $path" -ForegroundColor Green
Write-Host "Reminder: also handle mailbox, licences, devices, app-specific access and manager hand-over." -ForegroundColor Yellow
