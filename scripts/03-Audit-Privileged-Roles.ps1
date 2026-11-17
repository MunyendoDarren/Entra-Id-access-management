<#
.SYNOPSIS
  Audits who holds directory roles and flags risky patterns.
.DESCRIPTION
  Lists active role assignments and PIM-eligible assignments (if licensed), and flags:
   - high-privilege roles assigned directly (standing access)
   - too many / too few Global Administrators
   - groups holding privileged roles
  Output: console summary + CSV in /reports
#>
[CmdletBinding()]
param(
    [int]$MaxGlobalAdmins = 5
)

. (Join-Path $PSScriptRoot '../lib/Common.ps1')
Connect-EntraLab -Scopes 'RoleManagement.Read.Directory', 'RoleEligibilitySchedule.Read.Directory', 'Directory.Read.All'

$highPriv = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'User Administrator', 'Conditional Access Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'Exchange Administrator'
)

$roleMap = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleMap[$_.Id] = $_.DisplayName }

function Get-PrincipalInfo($principal) {
    $ap = $principal.AdditionalProperties
    [pscustomobject]@{
        Name = $ap['displayName']
        UPN  = $ap['userPrincipalName']
        Type = ($ap['@odata.type'] -replace '#microsoft.graph.', '')
    }
}

$findings = New-Object System.Collections.Generic.List[object]

# Active assignments
$active = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
foreach ($a in $active) {
    $role = $roleMap[$a.RoleDefinitionId]
    $who = Get-PrincipalInfo $a.Principal
    $flags = @()
    if ($role -in $highPriv) { $flags += 'High-privilege role (standing access - consider PIM eligible)' }
    if ($who.Type -eq 'group') { $flags += 'Role held via group - review group owners/members' }
    $findings.Add([pscustomobject]@{
        Role = $role; Principal = $who.Name; UPN = $who.UPN; PrincipalType = $who.Type
        AssignmentKind = 'Active'; Scope = $a.DirectoryScopeId; Flags = ($flags -join '; ')
    })
}

# Eligible assignments (needs Entra ID P2 / Governance)
try {
    $eligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty Principal -ErrorAction Stop
    foreach ($e in $eligible) {
        $who = Get-PrincipalInfo $e.Principal
        $findings.Add([pscustomobject]@{
            Role = $roleMap[$e.RoleDefinitionId]; Principal = $who.Name; UPN = $who.UPN; PrincipalType = $who.Type
            AssignmentKind = 'Eligible (PIM)'; Scope = $e.DirectoryScopeId; Flags = ''
        })
    }
}
catch { Write-Warning "Could not read PIM eligible assignments (requires Entra ID P2): $($_.Exception.Message)" }

# Global Admin count
$gaCount = @($findings | Where-Object { $_.Role -eq 'Global Administrator' -and $_.AssignmentKind -eq 'Active' -and $_.PrincipalType -eq 'user' }).Count
Write-Host "`nGlobal Administrators (active, users): $gaCount" -ForegroundColor Cyan
if ($gaCount -gt $MaxGlobalAdmins) { Write-Warning "More than $MaxGlobalAdmins Global Admins - reduce standing privilege." }
if ($gaCount -lt 2) { Write-Warning "Fewer than 2 Global Admins - make sure you have emergency access." }

$path = Get-ReportPath -Name 'privileged-roles'
$findings | Sort-Object Role, Principal | Export-Csv -NoTypeInformation -Path $path
$findings | Where-Object Flags | Format-Table Role, Principal, PrincipalType, Flags -AutoSize -Wrap
Write-Host "Report saved: $path" -ForegroundColor Green
