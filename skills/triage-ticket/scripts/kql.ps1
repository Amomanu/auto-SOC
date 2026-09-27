# kql.ps1 - run one KQL query as the least-privilege log-reader SP, then disconnect.
# Auth: DPAPI-encrypted secret at $HOME\.soc\triage-kql.secret (created once by the user; never echoed).
# Scope: "SOC Log Reader" custom role on <CLTA_WORKSPACE_NAME> - read log data only (no incident write, no Graph).
# Usage:
#   powershell -File kql.ps1 -QueryFile "<path to a file containing RAW KQL>"
#   powershell -File kql.ps1 -QueryFile "<...>" -WorkspaceId "<customerId>"   # default = CLTA <CLTA_WORKSPACE_NAME>
# Returns the Log Analytics query response JSON: { "tables":[{ "columns":[...], "rows":[...] }] }.
param(
  [Parameter(Mandatory)][string]$QueryFile,
  [string]$WorkspaceId = "<CLTA_WORKSPACE_ID>"   # CLTA <CLTA_WORKSPACE_NAME>
)
$ErrorActionPreference = "Stop"
$APP_ID = "<CLTA_LOGREADER_SP_APP_ID>"   # public client id - not a secret
$TENANT = "<CLTA_TENANT_ID>"   # Client A
$env:AZURE_CONFIG_DIR = "$HOME\.azure-triage-kql"  # isolate from admin + incident-SP sessions
try {
  $sec   = Get-Content "$HOME\.soc\triage-kql.secret" | ConvertTo-SecureString
  $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
  az login --service-principal -u $APP_ID -p $plain --tenant $TENANT --allow-no-subscriptions 1>$null
  $plain = $null
  $kql      = [System.IO.File]::ReadAllText($QueryFile)   # plain string - avoids PS 5.1 Get-Content -Raw note-props
  $bodyFile = [System.IO.Path]::GetTempFileName()
  # UTF-8 WITHOUT BOM - Set-Content -Encoding utf8 adds a BOM on PS 5.1 that the query API rejects.
  [System.IO.File]::WriteAllText($bodyFile, (@{ query = $kql } | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))
  az rest --method post --url "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query" --resource "https://api.loganalytics.io" --headers "Content-Type=application/json" --body "@$bodyFile"
  Remove-Item $bodyFile -Force -ErrorAction SilentlyContinue
}
finally {
  az logout 2>$null 1>$null
  Remove-Item Env:AZURE_CONFIG_DIR -ErrorAction SilentlyContinue
}
