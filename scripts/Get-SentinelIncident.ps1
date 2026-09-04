<#
.SYNOPSIS
    Read a Microsoft Sentinel incident via the Azure REST API - no MCP, no browser.

.DESCRIPTION
    Bridge for triage step 4 (the "is this incident still open?" gate) until the
    Sentinel MCP server is registered. Authenticates with the caller's existing
    'az login' session - no app registration, no client secret, no credentials
    entered anywhere.

    Uses Invoke-RestMethod rather than 'az rest' deliberately: az.cmd is a batch
    shim that mangles '&' in query strings and emits cp1252 encoding warnings that
    corrupt piped output.

.PARAMETER Client
    Client key (e.g. CLTA or CLTB). Resolves workspace, resource group, and subscription.

.PARAMETER Number
    Sentinel incident number, e.g. 192923. This is what Jira tickets reference.

.PARAMETER Id
    Incident GUID, if you have it instead of the number.

.PARAMETER IncludeAlerts
    Also fetch the incident's alerts.

.PARAMETER IncludeEntities
    Also fetch the incident's entities (accounts, hosts, IPs, mail messages).

.PARAMETER Raw
    Return the full PSObject instead of the formatted gate summary.

.EXAMPLE
    .\Get-SentinelIncident.ps1 -Client CLTA -Number 192923

.EXAMPLE
    .\Get-SentinelIncident.ps1 -Client CLTA -Number 192893 -IncludeEntities

.NOTES
    Some tenants may not be reachable from your primary 'az login' - their
    subscription may not be visible from the tenant your account can reach.
    Those need either a separate login or the app registration the MCP will use.
#>

[CmdletBinding(DefaultParameterSetName = 'ByNumber')]
param(
    [Parameter(Mandatory)][ValidateSet('CLTA', 'CLTB')][string]$Client,
    [Parameter(Mandatory, ParameterSetName = 'ByNumber')][int]$Number,
    [Parameter(Mandatory, ParameterSetName = 'ById')][string]$Id,
    [switch]$IncludeAlerts,
    [switch]$IncludeEntities,
    [switch]$Raw
)

$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'   # stops az CLI cp1252 warnings polluting stdout

$ApiVersion = '2024-03-01'

# --- per-client environment -------------------------------------------------
# Fill in your own subscription IDs, resource groups, and workspace names.
# Set Reachable = $false for tenants not visible to your primary az login.
$Env = @{
    CLTA = @{
        Subscription  = '<CLTA_SUBSCRIPTION_ID>'
        ResourceGroup = '<CLTA_RESOURCE_GROUP>'
        Workspace     = '<CLTA_WORKSPACE_NAME>'
        Reachable     = $true
    }
    CLTB = @{
        Subscription  = '<CLTB_SUBSCRIPTION_ID>'
        ResourceGroup = '<CLTB_RESOURCE_GROUP>'
        Workspace     = '<CLTB_WORKSPACE_NAME>'
        Reachable     = $false   # not visible to a primary az login - see .NOTES
    }
}

$cfg = $Env[$Client]

if (-not $cfg.Reachable) {
    Write-Warning "$Client's subscription is not reachable from your current 'az login'."
    Write-Warning "Verify with: az account list --all --query ""[?id=='$($cfg.Subscription)']"""
    Write-Warning "Until the app registration lands, use the browser path for $Client."
    return
}

# --- auth: reuse the existing az session, never a stored secret --------------
try {
    $tokenJson = az account get-access-token --resource https://management.azure.com --only-show-errors 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $tokenJson) { throw 'az returned no token' }
    $token = ($tokenJson | ConvertFrom-Json).accessToken
}
catch {
    throw "Could not get an Azure token. Run 'az login' first. ($_)"
}

$headers = @{ Authorization = "Bearer $token" }
$base = "https://management.azure.com/subscriptions/$($cfg.Subscription)" +
        "/resourceGroups/$($cfg.ResourceGroup)" +
        "/providers/Microsoft.OperationalInsights/workspaces/$($cfg.Workspace)" +
        "/providers/Microsoft.SecurityInsights"

function Invoke-Sentinel([string]$RelativeUri) {
    Invoke-RestMethod -Uri "$base/$RelativeUri" -Headers $headers -Method Get
}

# --- resolve the incident ---------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'ById') {
    $incident = Invoke-Sentinel "incidents/$Id`?api-version=$ApiVersion"
}
else {
    $filter = [uri]::EscapeDataString("properties/incidentNumber eq $Number")
    try {
        $hits = Invoke-Sentinel "incidents?api-version=$ApiVersion&`$filter=$filter"
        $incident = $hits.value | Select-Object -First 1
    }
    catch {
        Write-Verbose 'OData filter rejected; paging instead.'
        $incident = $null
        $next = "$base/incidents?api-version=$ApiVersion"
        $pages = 0
        while ($next -and -not $incident -and $pages -lt 40) {
            $page = Invoke-RestMethod -Uri $next -Headers $headers -Method Get
            $incident = $page.value | Where-Object { $_.properties.incidentNumber -eq $Number }
            $next = $page.nextLink
            $pages++
        }
    }
}

if (-not $incident) { throw "Incident $Number not found in $($cfg.Workspace)." }
if ($Raw) { return $incident }

# --- gate summary -----------------------------------------------------------
$p = $incident.properties
$isOpen = $p.status -in @('New', 'Active')

$ownerName = if ($p.owner.assignedTo) { $p.owner.assignedTo }
             elseif ($p.owner.userPrincipalName) { $p.owner.userPrincipalName }
             elseif ($p.owner.email) { $p.owner.email }
             else { $null }

$out = [ordered]@{
    Client        = $Client
    Workspace     = $cfg.Workspace
    Number        = $p.incidentNumber
    Guid          = $incident.name
    Title         = $p.title
    Severity      = $p.severity
    Status        = $p.status
    Gate          = if ($isOpen) { 'OPEN -> continue triage' } else { 'CLOSED -> short-circuit' }
    Classification = $p.classification
    ClosureNote   = $p.classificationComment
    Owner         = $ownerName
    Created       = $p.createdTimeUtc
    LastModified  = $p.lastModifiedTimeUtc
    Url           = $p.incidentUrl
}

if ($IncludeAlerts) {
    $alerts = Invoke-RestMethod -Uri "$base/incidents/$($incident.name)/alerts?api-version=$ApiVersion" `
                                -Headers $headers -Method Post
    $out.Alerts = $alerts.value | ForEach-Object {
        [pscustomobject]@{
            Name     = $_.properties.alertDisplayName
            Severity = $_.properties.alertSeverity
            Provider = $_.properties.productName
            Start    = $_.properties.startTimeUtc
        }
    }
}

if ($IncludeEntities) {
    $entities = Invoke-RestMethod -Uri "$base/incidents/$($incident.name)/entities?api-version=$ApiVersion" `
                                  -Headers $headers -Method Post
    $out.Entities = $entities.entities | ForEach-Object {
        [pscustomobject]@{
            Kind = $_.kind
            Value = $_.properties.friendlyName
        }
    }
}

[pscustomobject]$out
