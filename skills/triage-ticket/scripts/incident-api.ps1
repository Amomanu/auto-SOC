# incident-api.ps1 - connect as the least-privilege Sentinel incident SP, do one call, disconnect.
# Auth: DPAPI-encrypted secret at $HOME\.soc\triage-sp.secret (created once by the user; never echoed).
# Scope: "SOC Incident Lifecycle" custom role on the CLTA <CLTA_WORKSPACE_NAME> workspace (incidents read/write + comments).
# Usage:
#   powershell -File incident-api.ps1 -Method get -Url "<ARM incident URL>"
#   powershell -File incident-api.ps1 -Method put -Url "<...>" -BodyFile "<path to close.json>"   # preferred for PUT
#   powershell -File incident-api.ps1 -Method put -Url "<...>" -Body '<json>'                     # small inline bodies only
param(
  [Parameter(Mandatory)][ValidateSet("get","put","post","patch","delete")][string]$Method,
  [Parameter(Mandatory)][string]$Url,
  [string]$Body,
  [string]$BodyFile   # path to a JSON body file (preferred for PUT/close; avoids quote mangling)
)
$ErrorActionPreference = "Stop"
$APP_ID = "<CLTA_INCIDENT_SP_APP_ID>"   # public client id - not a secret
$TENANT = "<CLTA_TENANT_ID>"   # Client A
$env:AZURE_CONFIG_DIR = "$HOME\.azure-triage-sp"   # isolate from the admin az session
try {
  $sec   = Get-Content "$HOME\.soc\triage-sp.secret" | ConvertTo-SecureString
  $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
  az login --service-principal -u $APP_ID -p $plain --tenant $TENANT --allow-no-subscriptions 1>$null
  $plain = $null
  if ($BodyFile) { az rest --method $Method --url $Url --headers "Content-Type=application/json" --body "@$BodyFile" }
  elseif ($Body) { az rest --method $Method --url $Url --headers "Content-Type=application/json" --body $Body }
  else           { az rest --method $Method --url $Url }
}
finally {
  az logout 2>$null 1>$null
  Remove-Item Env:AZURE_CONFIG_DIR -ErrorAction SilentlyContinue
}
