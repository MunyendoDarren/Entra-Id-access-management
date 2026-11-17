<#
.SYNOPSIS
  Deploys a baseline set of Conditional Access policies (report-only by default).
.DESCRIPTION
  CA001  Require MFA for all users
  CA002  Require MFA for administrator roles
  CA003  Block legacy authentication
  All policies exclude the SG-BreakGlass group so you cannot lock yourself out.
  Policies are created in REPORT-ONLY mode. Review the sign-in logs (Conditional Access tab)
  before using -Enforce.
.NOTES
  Requires Entra ID P1. Security Defaults must be OFF to use Conditional Access.
#>
[CmdletBinding()]
param(
    [string]$BreakGlassGroupName = 'SG-BreakGlass',
    [switch]$Enforce
)

. (Join-Path $PSScriptRoot '../lib/Common.ps1')
Connect-EntraLab -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Application.Read.All', 'Group.Read.All'

$state = if ($Enforce) { 'enabled' } else { 'enabledForReportingButNotEnforced' }
if ($Enforce) {
    Write-Warning "ENFORCE mode: make sure your emergency-access accounts are in $BreakGlassGroupName and tested."
}

$bg = Get-MgGroup -Filter "displayName eq '$BreakGlassGroupName'" | Select-Object -First 1
if (-not $bg) { throw "Group '$BreakGlassGroupName' not found. Run 01-Setup-Lab.ps1 first." }

# Built-in role template IDs
$adminRoles = @(
    '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814', # Privileged Role Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d', # Security Administrator
    'fe930be7-5e62-47db-91af-98c3a49a38b1', # User Administrator
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'  # Conditional Access Administrator
)

$policies = @(
    @{
        displayName   = 'CA001 - Require MFA for all users'
        state         = $state
        conditions    = @{
            users          = @{ includeUsers = @('All'); excludeGroups = @($bg.Id) }
            applications   = @{ includeApplications = @('All') }
            clientAppTypes = @('all')
        }
        grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
    },
    @{
        displayName   = 'CA002 - Require MFA for administrator roles'
        state         = $state
        conditions    = @{
            users          = @{ includeRoles = $adminRoles; excludeGroups = @($bg.Id) }
            applications   = @{ includeApplications = @('All') }
            clientAppTypes = @('all')
        }
        grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
    },
    @{
        displayName   = 'CA003 - Block legacy authentication'
        state         = $state
        conditions    = @{
            users          = @{ includeUsers = @('All'); excludeGroups = @($bg.Id) }
            applications   = @{ includeApplications = @('All') }
            clientAppTypes = @('exchangeActiveSync', 'other')
        }
        grantControls = @{ operator = 'OR'; builtInControls = @('block') }
    }
)

$existing = Get-MgIdentityConditionalAccessPolicy -All
foreach ($p in $policies) {
    if ($existing | Where-Object DisplayName -eq $p.displayName) {
        Write-Host "= $($p.displayName) already exists - skipped"
        continue
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $p | Out-Null
    Write-Host "+ created: $($p.displayName)  [$state]" -ForegroundColor Cyan
}
