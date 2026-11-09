# jira.ps1 - Jira Cloud REST fallback for when the Atlassian Rovo connector drops out of the session.
# Auth: Atlassian API token (basic auth), DPAPI-encrypted at $HOME\.soc\jira-api.secret, account email in
#       $HOME\.soc\jira-api.email. Both created once by the user (never echoed):
#   New-Item -ItemType Directory -Force "$HOME\.soc" | Out-Null
#   Set-Content "$HOME\.soc\jira-api.email" "<your Atlassian login email>"
#   Read-Host "Jira API token" -AsSecureString | ConvertFrom-SecureString | Set-Content "$HOME\.soc\jira-api.secret"
# From Git Bash, prefix MSYS_NO_PATHCONV=1 or a -Path without "?" gets rewritten to "C:/Program Files/Git/rest/...".
# Usage:
#   powershell -File jira.ps1 -Method get  -Path "/rest/api/3/issue/CLTB-1234?fields=summary,status"
#   powershell -File jira.ps1 -Method post -Path "/rest/api/3/search/jql" -BodyFile "<query.json>"
#   powershell -File jira.ps1 -Method get  -Path "/rest/api/3/issue/CLTB-1234/transitions"
#   powershell -File jira.ps1 -Method post -Path "/rest/api/3/issue/CLTB-1234/transitions" -BodyFile "<t.json>"
#   # JSM comments: internal by default via servicedeskapi; body {"body":"text","public":false}
#   powershell -File jira.ps1 -Method post -Path "/rest/servicedeskapi/request/CLTB-1234/comment" -BodyFile "<c.json>"
param(
  [Parameter(Mandatory)][ValidateSet("get","put","post","delete")][string]$Method,
  [Parameter(Mandatory)][string]$Path,
  [string]$Body,
  [string]$BodyFile,   # path to a JSON body file (preferred; avoids quote mangling)
  [string]$Site = "https://<JIRA_SITE>.atlassian.net"
)
$ErrorActionPreference = "Stop"
$email = (Get-Content "$HOME\.soc\jira-api.email" -Raw).Trim()
$sec   = Get-Content "$HOME\.soc\jira-api.secret" | ConvertTo-SecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
$auth  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${email}:${plain}"))
$plain = $null
$headers = @{ Authorization = "Basic $auth"; Accept = "application/json" }
$args_ = @{ Method = $Method; Uri = "$Site$Path"; Headers = $headers }
if ($BodyFile) { $args_.Body = [IO.File]::ReadAllBytes($BodyFile); $args_.ContentType = "application/json; charset=utf-8" }
elseif ($Body) { $args_.Body = [Text.Encoding]::UTF8.GetBytes($Body); $args_.ContentType = "application/json; charset=utf-8" }
try {
  $r = Invoke-RestMethod @args_
  if ($null -ne $r) { $r | ConvertTo-Json -Depth 30 }
}
catch {
  $code = $_.Exception.Response.StatusCode.value__
  Write-Error "Jira $Method $Path failed (HTTP $code): $($_.ErrorDetails.Message)"
}
