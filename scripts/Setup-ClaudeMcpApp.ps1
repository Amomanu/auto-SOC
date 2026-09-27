# Setup-ClaudeMcpApp.ps1
# Provisions the Microsoft MCP Server for Enterprise and registers a custom
# client app (delegated, read-only MCP scopes) for connecting an MCP client.
#
# Run in PowerShell 7 (pwsh), signed in as an admin of the target tenant.
# Role required: Application Administrator or Cloud Application Administrator.

# 0. Load the module
Import-Module Microsoft.Entra.Beta.Authentication -Force

# 1. Sign in to the TARGET tenant
Connect-Entra -Scopes 'Application.ReadWrite.All','Directory.Read.All','DelegatedPermissionGrant.ReadWrite.All' `
              -TenantId '<YOUR_TENANT_ID>'
Get-EntraContext          # checkpoint: verify Account + TenantId are correct

# 2. One-time tenant provisioning of the MCP server (safe to re-run)
Grant-EntraBetaMCPServerPermission -ApplicationName VisualStudioCode

# 3. Create the client app registration (single tenant)
$app = New-EntraBetaApplication -DisplayName 'MCP - Graph Enterprise' `
                                -SignInAudience 'AzureADMyOrg'

# 4. Create its service principal (required before consent)
$sp = New-EntraBetaServicePrincipal -AppId $app.AppId

# 5. Assign MCP scopes + grant admin consent (all delegated, read-only)
$scopes = @(
    'MCP.User.Read.All'
    'MCP.Group.Read.All'
    'MCP.AuditLog.Read.All'
    'MCP.SecurityIncident.Read.All'
    'MCP.SecurityAlert.Read.All'
    'MCP.Application.Read.All'
)
Grant-EntraBetaMCPServerPermission -ApplicationId $app.AppId -Scopes $scopes

# 6. Print what you need for the MCP client
Write-Host "`n=== SAVE THESE ===" -ForegroundColor Cyan
Write-Host "Client (Application) ID : $($app.AppId)"
Write-Host "Tenant (Directory) ID   : $((Get-EntraContext).TenantId)"
