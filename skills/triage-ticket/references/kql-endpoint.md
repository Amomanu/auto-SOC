# KQL cookbook — Endpoint / Defender-XDR LOLBin behavior (image loads, process, network)

Covers Sentinel scheduled-analytics and Defender/XDR detections that fire on **endpoint
process behavior** — e.g. "Regsvr32 Rundll32 Image Loads Abnormal Extension", suspicious
LOLBin execution, unusual DLL/image loads, script-host spawns. Source telemetry is the
**MDE device tables**, which in this tenant are streamed into the Log Analytics workspace
(`<CLTA_WORKSPACE_NAME>`) and queryable via terminal `az rest` (see SKILL.md §0 for workspace IDs and
the `az rest` pattern).

Core tables:
- `DeviceImageLoadEvents` — DLL/image loads (FileName, FolderPath, SHA1/SHA256, InitiatingProcess*)
- `DeviceProcessEvents` — process creation + full command lines, parent process, account
- `DeviceNetworkEvents` — outbound/inbound connections (RemoteIP, RemotePort, RemoteUrl, InitiatingProcess*)
- `DeviceFileCertificateInfo` — Authenticode signer/issuer for a SHA1 (signature validation)
- `SecurityAlert` — cross-product alert sweep for a host

## Account/host resolution first
- The alert entity is a **device name** (e.g. `tosj0gpdc4`), not a UPN. Key every query on
  `DeviceName has "<host>"`.
- Portal alert Start/End times are **UTC** in the Logs "Link to LA" context — confirmed by the
  rule's own `set query_now = datetime(...Z)`. But the incident **Overview** card shows local
  (EDT). Don't mix them; prefer `ago()` windows over fixed timestamps.

## Query patterns

### 1. Reproduce the exact rule match (image-load detections)
```
DeviceImageLoadEvents
| where Timestamp > ago(3d)
| where DeviceName has "<host>"
| where InitiatingProcessFileName =~ "regsvr32.exe" or InitiatingProcessFileName =~ "rundll32.exe"
| where FileName !endswith ".dll"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA1
| take 50
```

### 2. Characterise the burst — is it one transaction?
Group the .tmp/.abnormal loads by initiating/parent process and account. A tight burst
(seconds) all parented by `msiexec.exe` under `system` = an install/patch transaction.

### 3. Disconfirming test — the network half
The rule "joins to public network events." Pull the flagged RemoteIP and see **which process**
made it and to **what URL**:
```
DeviceNetworkEvents
| where Timestamp > ago(3d)
| where DeviceName has "<host>"
| where RemoteIP == "<flagged IP>"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl, InitiatingProcessParentFileName
| take 50
```
If **multiple unrelated processes** (and multiple user accounts) hit the same IP on **:80** with
a `RemoteUrl` of `http://ocsp.<ca>.com/...`, it is a shared **OCSP certificate-revocation
endpoint**, not a per-process C2 channel.

### 4. Host-scoped alert sweep (breadth)
```
SecurityAlert
| where TimeGenerated > ago(7d)
| where Entities has "<host>"
| project TimeGenerated, AlertName, AlertSeverity, Status, ProductName
| take 50
```

## Traps
- **Scope by `ago()` in every query.** A narrow default time window can cause a host-scoped
  `SecurityAlert` / 7-day query to return zero rows even though data exists. Always use explicit
  `ago(7d)` or wider scopes. Validate the zero by confirming the query returns the incident's
  **own** alert.
- **Avoid `count()` / `in (...)` when constructing KQL for terminal** — prefer OR'd `=~` equalities
  and `take`/`distinct` to reduce escaping issues. Read the query back before running.
- **`.tmp` in `C:\Windows\Installer\` loaded by rundll32 is not "masquerading."** It is the
  WiX/DTF pattern (see below). Read the command line before assessing.

## Classification logic — regsvr32/rundll32 abnormal-extension image loads
The **benign/WiX signature** (→ False Positive, tune):
- Command line: `rundll32.exe "C:\Windows\Installer\<MSIxxxx>.tmp",zzzzInvokeManagedCustomActionOutOfProc SfxCA_...`
- `SfxCA_*` + `zzzzInvokeManagedCustomActionOutOfProc` = WiX toolset **managed custom-action host**.
  msiexec extracts the self-extracting CA DLL into `C:\Windows\Installer` as a `.tmp` and invokes
  it via rundll32. The `.tmp` **is** a DLL; the extension is installer naming, not evasion.
- Account `system`, parent `msiexec.exe`, tight burst = MSI install/patch (incl. Azure VM
  extension updates, which install via msiexec as SYSTEM).
- Any joined public-network connection is typically the installer's **OCSP signature check**
  (`http://ocsp.digicert.com`, :80).
- Verdict: **False Positive — overbroad rule misfires on WiX MSI custom actions.** Recommend a
  rule exclusion for `FolderPath startswith "C:\\Windows\\Installer\\"` + `FileName endswith ".tmp"`
  + `InitiatingProcessParentFileName =~ "msiexec.exe"` + command line contains
  `zzzzInvokeManagedCustomActionOutOfProc`.

The **would-be-malicious** shape (→ escalate): rundll32/regsvr32 loading an odd-extension image
from a **user-writable / temp / web-download path**, parented by a browser/office/script host,
running as a **user** (not SYSTEM/msiexec), with a **beaconing** egress to a non-CA IP. None of
this was present here.

---

## Detection family — Windows Defender exclusion tamper ("Malware Hides Itself Among Windows Defender Exclusions", MosaicLoader)

Sentinel scheduled rule that fires on **any write to the Defender Exclusions registry keys**. Source
table `DeviceRegistryEvents`. The rule (as shipped) keys purely on the registry key path and does
**not** inspect who wrote it or what was excluded — so it fires on legitimate exclusion registration
just as readily as on malware. Kill-chain tag is always **DefenseEvasion** (the rule's inherent tag,
not observed adversary behavior). Alert entity is a **device name**, not a UPN.

The exact shipped rule logic:
```
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
    and (RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
      or RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
      or RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes")
```
The excluded item is the **`RegistryValueName`** (e.g. a full exe path or an extension); `RegistryValueData`
is a Dword `0`. `Exclusions\Paths` = folder/path exclusion, `\Processes` = process exclusion,
`\Extensions` = file-extension exclusion.

### Query patterns

**1. Reproduce the match + read WHO wrote it and WHAT was excluded** (the crux). Get the full row:
```
DeviceRegistryEvents
| where DeviceName has "<host>"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions"
| where Timestamp between (datetime(<alert-min-Z>) .. datetime(<alert-max-Z>))
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, ActionType,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName,
          PreviousRegistryValueName
| sort by Timestamp asc
```
Read `InitiatingProcessFileName`/`FolderPath` and the VersionInfo (CompanyName, FileDescription):
- **`msmpeng.exe`** from `…\Windows Defender\Platform\<ver>\MsMpEng.exe`, account `system`, CompanyName
  **Microsoft Corporation**, FileDescription **Antimalware Service Executable** = the exclusion was applied
  through the **proper Defender channel** (admin, Intune/MDE/GPO policy, Windows Security UI, an app
  installer's Add-MpPreference, or a Defender platform-update re-commit). Defender itself commits the value.
- `PreviousRegistryValueName == RegistryValueName` = the exclusion **already existed** and was re-written
  unchanged (policy sync / platform update re-commit), not freshly injected.

**2. Was the exclusion long-standing or newly injected?** (history)
```
DeviceRegistryEvents
| where DeviceName has "<host>"
| where RegistryKey has @"Windows Defender\Exclusions"
| where Timestamp > ago(90d)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Writes=count()
    by RegistryValueName, InitiatingProcessFileName, ActionType
| sort by RegistryValueName asc
```

**3. Is the excluded target a real, legitimately-used app?** (disconfirming)
```
DeviceProcessEvents
| where DeviceName has "<host>"
| where Timestamp > ago(30d)
| where FolderPath has "<excluded-app-dir>" or FileName startswith "<excluded-app>"
| summarize Runs=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by FileName, FolderPath, InitiatingProcessAccountName
| sort by LastSeen desc
```
Real end users running the app from its **standard `C:\Program Files\<vendor>\` path** — and an
**installer/setup** running from a user Downloads dir near the alert time — confirms a legit
install/update that registered the vendor's own Defender exclusions.

**4. Any actual malware on the host?** (breadth — must accompany any FP call)
```
DeviceEvents
| where DeviceName has "<host>"
| where Timestamp > ago(14d)
| where ActionType has_any ("Antivirus","Malware","Quarantine","Amsi","Asr","ExploitGuard","SmartScreen")
| summarize Count=count(), Last=max(Timestamp) by ActionType
```
**Validate the zero** with the companion (proves the table is populated for the host):
```
DeviceEvents | where DeviceName has "<host>" | where Timestamp > ago(14d)
| summarize Count=count(), Last=max(Timestamp) by ActionType | sort by Count desc | take 20
```

### Traps
- **The alert entity resolves the host but the two "extra" alert entities show as `0`** — those are the
  excluded-path registry entities that didn't resolve to named entities. Not evidence of anything.
- **`RegistryValueData` is always `0`** for a Defender exclusion — it is not a payload; ignore it. The
  signal is the `RegistryValueName` (the excluded path/extension) and the initiating process.
- The incident **Entities**/**Top insights** cards in the new Azure incident page frequently render
  "Something went wrong" — use the alert flyout's **Events → Link to LA** to get the exact rule query and
  matched rows instead.

### Classification logic — Defender exclusion tamper
The **benign/legit-software signature** (→ False Positive, tune):
- Initiating process **`MsMpEng.exe`** (Microsoft-signed, `…\Windows Defender\Platform\…`), account SYSTEM.
- Excluded `RegistryValueName` is a **legitimate signed application in `C:\Program Files\<vendor>\`**
  (e.g. `C:\Program Files\FreeFileSync\FreeFileSync.exe`), corroborated by real end users running that app
  and/or a vendor installer running near the alert time.
- `PreviousRegistryValueName == RegistryValueName` (pre-existing exclusion re-committed) and/or the write
  coincides with a **Defender platform update** or **app install/update**.
- **No** AV/Malware/Quarantine detections on the host (validated non-empty companion).
- Verdict: **False Positive — overbroad "Defender exclusion tamper" rule misfires on legitimate software
  registering its own exclusions.** Recommend tuning: allow-list exclusion writes whose `RegistryValueName`
  is a known-good vendor path under `C:\Program Files\`, and reserve the alert for exclusions pointing at
  **user-writable / temp / ProgramData / AppData / web-download** paths.

The **would-be-malicious** shape (→ escalate): an exclusion for a path in a **user-writable / temp /
AppData / ProgramData** location, or for a broad path (`C:\`, a whole user profile) or a scripting
extension (`.ps1`, `.exe` globally); set **shortly after** a suspicious dropper/LOLBin execution or an
AV detection on the host; especially where the excluded binary is unsigned or has no run history as a
known app. MosaicLoader proper drops to `%ProgramData%`/`%LOCALAPPDATA%` and excludes *that* — not a
Program Files vendor app.
