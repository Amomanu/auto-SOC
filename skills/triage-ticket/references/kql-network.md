# KQL cookbook — network / Azure WAF (Application Gateway, Front Door)

Self-contained. Covers Sentinel scheduled rules that fire on Azure WAF pattern matches
(e.g. "Azure WAF matching for Log4j vuln(CVE-2021-44228)", template `2de8abd6-…`).
Source telemetry: `AzureDiagnostics` with `ResourceProvider == "MICROSOFT.NETWORK"`.

| Category | Holds | Key columns |
|---|---|---|
| `ApplicationGatewayFirewallLog` / `FrontdoorWebApplicationFirewallLog` | one row per WAF rule hit | `clientIp_s`, `hostname_s`, `requestUri_s`, `ruleId_s`, `ruleSetType_s`, `action_s`, `Message`, `details_data_s`, `transactionId_g` |
| `ApplicationGatewayAccessLog` / `FrontdoorAccessLog` | one row per request — the **response** | `clientIP_s`, `host_s`, `originalHost_s`, `requestUri_s`, `httpStatus_d`, `serverRouted_s`, `userAgent_s`, `transactionId_g` |

CLTA: three gateways — `<APPGW_PROD_1>`, `<APPGW_PROD_2>`, `<APPGW_DEV_1>`. Front Door
logs not observed (CLTA-39985).

## Query patterns

### 1. Reproduce the rule hits — payload, target, action
```kusto
let log4jioc = dynamic(["jndi","ldap","${::"]);
AzureDiagnostics
| where TimeGenerated between (<RULE_QUERY_START> .. <RULE_QUERY_END>)   // from alert ExtendedProperties
| where ResourceProvider == "MICROSOFT.NETWORK" and Category in ("ApplicationGatewayFirewallLog", "FrontdoorWebApplicationFirewallLog")
| where requestUri_s has_any (log4jioc) or details_message_s has_any (log4jioc) or details_data_s has_any (log4jioc)
| summarize n=count(), fst=min(TimeGenerated), lst=max(TimeGenerated), actions=make_set(action_s), rules=make_set(ruleId_s),
            data=make_set(substring(details_data_s, 0, 300), 8), uris=make_set(substring(requestUri_s,0,200), 8)
  by clientIp_s, Resource, hostname_s
```
Read `details_data_s`: it shows the header that carried the payload and the **callback host**.
A callback to `127.0.0.1` / loopback cannot reach an attacker — that is a scanner probe, not a
weaponized exploit. An external callback host/IP is the pivot for step 4.

### 2. Disconfirming test — did the request reach the backend, and what came back
Join the WAF hits to the access log on `transactionId_g`.
```kusto
let tx = AzureDiagnostics
| where TimeGenerated between (<START> .. <END>)
| where Category == "ApplicationGatewayFirewallLog" and ruleId_s == "<RULE_ID>" and clientIp_s == "<SOURCE_IP>"
| distinct transactionId_g;
AzureDiagnostics
| where TimeGenerated between (<START> .. <END>)
| where Category == "ApplicationGatewayAccessLog" and transactionId_g in (tx)
| summarize n=count(), uris=make_set(requestUri_s, 5), backends=make_set(serverRouted_s, 5), ua=make_set(substring(userAgent_s,0,120), 5)
  by httpStatus_d, host_s, originalHost_s
```

### 3. WAF mode per gateway — is it blocking at all?
```kusto
AzureDiagnostics
| where TimeGenerated > ago(3d)
| where Category == "ApplicationGatewayFirewallLog"
| summarize n=count() by Resource, action_s
```
`Detected` on anomaly rule `949110` with no `Blocked` rows = the policy is in **Detection** mode;
every matched request was forwarded to the backend.

### 4. Source IP footprint — campaign breadth and follow-on
```kusto
AzureDiagnostics
| where TimeGenerated > ago(3d)
| where ResourceProvider == "MICROSOFT.NETWORK" and Category == "ApplicationGatewayFirewallLog"
| where clientIp_s == "<SOURCE_IP>"
| summarize n=count(), fst=min(TimeGenerated), lst=max(TimeGenerated), rules=make_set(ruleId_s, 20) by Resource, action_s, hostname_s, ruleSetType_s
```
```kusto
union isfuzzy=true
 (DeviceNetworkEvents | where TimeGenerated > ago(30d) | where RemoteIP == "<SOURCE_IP>"
   | summarize n=count(), fst=min(TimeGenerated), lst=max(TimeGenerated), ports=make_set(LocalPort) by Src="DNE", DeviceName, ActionType),
 (DeviceLogonEvents | where TimeGenerated > ago(30d) | where RemoteIP == "<SOURCE_IP>"
   | summarize n=count(), fst=min(TimeGenerated), lst=max(TimeGenerated), accts=make_set(AccountName) by Src="DLE", DeviceName, ActionType),
 (SigninLogs | where TimeGenerated > ago(30d) | where IPAddress == "<SOURCE_IP>" | summarize n=count() by Src="Signin", DeviceName=UserPrincipalName, ActionType=ResultType),
 (ThreatIntelligenceIndicator | where TimeGenerated > ago(90d) | where NetworkIP == "<SOURCE_IP>" or NetworkSourceIP == "<SOURCE_IP>" | summarize n=count() by Src="TI", DeviceName=tostring(Description), ActionType=tostring(Tags))
```
`InboundConnectionAccepted` is only a TCP handshake — the verdict turns on `LogonSuccess` in
`DeviceLogonEvents`. Validate `DeviceLogonEvents` is populated for the named devices before
treating zero rows as clean.

## Traps
| Trap | Symptom | Workaround |
|---|---|---|
| `first` / `last` are reserved in KQL | `SYN0002 Query could not be parsed at 'first'` | name aggregates `fst` / `lst` |
| Access-log client IP column is `clientIP_s` (capital IP); WAF log is `clientIp_s` | empty join / filter | use the right one per category |
| WAF in Detection mode | `action_s` = `Matched`/`Detected`, never `Blocked`; access log shows 200 | do not read the alert as "blocked"; a 200 only means the backend answered `GET /` |
| Single `extract(@"://…")` for the callback host | ~60% of rows return junk (`found within [REQUEST_HEADERS`) — it grabs the empty host after the matched `${jndi:ldap://` prefix | `extend hosts = extract_all(@"://([A-Za-z0-9\.\-]+)", details_data_s) \| mv-expand h = hosts to typeof(string) \| summarize count() by h` (CLTA-40031) |
| `.invalid` callback host | e.g. `log4shell-pci-scan.invalid` | RFC 2606 reserved TLD — cannot resolve, so no callback is possible; treat like loopback |
| Alert window vs. campaign | rule only sees a 6h window | widen to `ago(3d)` on the IP — scanners hit every gateway |

## Classification logic
- **True Positive, unsuccessful** — real exploit/scan traffic (scanner UA, many signatures,
  default-cred logon attempts), but no successful follow-on: loopback or no callback, no
  `LogonSuccess`, no backend process/network evidence.
- **True Positive, compromise** — an external JNDI callback host that a backend host is seen
  contacting (`DeviceNetworkEvents` / DNS), or `LogonSuccess` from the source IP.
- **Benign Positive** — the client confirms an authorized scan (e.g. a PCI ASV) from that IP.
- **False Positive** — the IOC string matched legitimate content (a `jndi`/`ldap` token in a normal
  query string) with no exploit syntax.
