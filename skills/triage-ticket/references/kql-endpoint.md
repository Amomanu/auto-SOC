# KQL — Endpoint LOLBin / Defender-exclusion detections (`kql-endpoint.md`)

For Sentinel rules sourced from Microsoft Defender for Endpoint: LOLBin execution
(regsvr32, rundll32, mshta, certutil, etc.), Defender AV exclusion tampering, suspicious
process chains, and device anomaly alerts. Core tables: `DeviceProcessEvents`,
`DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceNetworkEvents`, `DeviceImageLoadEvents`,
`SecurityAlert`. Some tables live in **Defender Advanced Hunting** only (check the ingestion
map), while `SecurityAlert` is in the Sentinel workspace.

> Universal KQL conventions (validate every zero-row negative, `ago()`-scope-then-narrow, KQL mode,
> terminal KQL conventions) live in the skill body. This file carries only the endpoint-family
> patterns, traps, and reference tables.

## Detection family 1: LOLBin image loads (regsvr32 / rundll32 / mshta)

### What the rule detects
Execution of living-off-the-land binaries that can proxy DLL loads or script execution.
The rule fires on the **image load** or **process creation** event, not on the outcome.
The decisive question is: *what did it load, and was it expected?*

### Characterise the process chain
```kusto
DeviceProcessEvents
| where TimeGenerated > ago(3d)
| where DeviceName has "<host>"
| where FileName has_any ("regsvr32.exe", "rundll32.exe", "mshta.exe", "certutil.exe")
| project TimeGenerated, DeviceName, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AccountName,
    FolderPath, ProcessId, InitiatingProcessId
| order by TimeGenerated asc
```

### Image loads by the LOLBin process
```kusto
DeviceImageLoadEvents
| where TimeGenerated > ago(3d)
| where DeviceName has "<host>"
| where InitiatingProcessFileName has_any ("regsvr32.exe", "rundll32.exe")
| project TimeGenerated, FileName, FolderPath,
    SHA256, InitiatingProcessCommandLine,
    InitiatingProcessFolderPath
| order by TimeGenerated asc
```

### Network connections from the LOLBin
```kusto
DeviceNetworkEvents
| where TimeGenerated > ago(3d)
| where DeviceName has "<host>"
| where InitiatingProcessFileName has_any ("regsvr32.exe", "rundll32.exe", "mshta.exe")
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### File writes by the process
```kusto
DeviceFileEvents
| where TimeGenerated > ago(3d)
| where DeviceName has "<host>"
| where InitiatingProcessFileName has_any ("regsvr32.exe", "rundll32.exe")
| where ActionType has_any ("FileCreated", "FileModified")
| project TimeGenerated, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### Baseline: is this LOLBin normal on this host?
```kusto
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where DeviceName has "<host>"
| where FileName has "<lolbin>"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated),
    DistinctCmdLines=dcount(ProcessCommandLine)
    by FileName, InitiatingProcessFileName
| order by Count desc
```

## Detection family 2: Defender AV exclusion tampering

### What the rule detects
A registry or policy change that adds, modifies, or removes a Defender AV exclusion
(path, extension, or process). The exclusion change itself is the event — the question is
*who made it and why*.

### Registry exclusion changes
```kusto
DeviceRegistryEvents
| where TimeGenerated > ago(3d)
| where DeviceName has "<host>"
| where RegistryKey has "Windows Defender" and RegistryKey has "Exclusions"
| project TimeGenerated, DeviceName, ActionType,
    RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by TimeGenerated asc
```

### Who set the exclusion — process chain
```kusto
DeviceProcessEvents
| where TimeGenerated > ago(3d)
| where DeviceName has "<host>"
| where ProcessCommandLine has "Exclusion"
    or ProcessCommandLine has "Add-MpPreference"
    or ProcessCommandLine has "Set-MpPreference"
| project TimeGenerated, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName, AccountDomain
| order by TimeGenerated asc
```

### Exclusion breadth — what is now excluded?
```kusto
DeviceRegistryEvents
| where TimeGenerated > ago(30d)
| where DeviceName has "<host>"
| where RegistryKey has "Windows Defender" and RegistryKey has "Exclusions"
| summarize Count=count(), Last=max(TimeGenerated)
    by RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by Last desc
```

### Correlated malware — did anything run from the excluded path?
```kusto
DeviceProcessEvents
| where TimeGenerated > ago(3d)
| where DeviceName has "<host>"
| where FolderPath has "<excluded_path>"
| project TimeGenerated, FileName, FolderPath, SHA256,
    ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by TimeGenerated asc
```

### Tenant-wide exclusion sweep
Check if the same exclusion was pushed to multiple devices (GPO or Intune deployment vs.
local tampering).
```kusto
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
| where RegistryKey has "Windows Defender" and RegistryKey has "Exclusions"
| where RegistryValueData has "<excluded_value>"
| summarize Devices=dcount(DeviceName), Count=count()
    by RegistryValueName, RegistryValueData, ActionType
```

## Traps (endpoint-specific)

| Trap | Symptom | Workaround |
|------|---------|------------|
| Tables not in Sentinel | `DeviceProcessEvents` returns zero in Log Analytics | Check ingestion map — these tables may live in Defender AH only |
| LOLBin ≠ malware | regsvr32/rundll32 are legitimate Windows components used constantly | Baseline the host first; the DLL it loaded and the parent process are what matter |
| GPO-deployed exclusions | Exclusion change fires on every device in the OU | Check breadth — if 50 devices got the same exclusion at the same time, it's policy |
| `ProcessCommandLine` truncation | Long command lines are clipped in the table | Use `has` rather than exact match; for full command lines, check the process tree |
| Hash mismatch across tables | SHA256 in `DeviceFileEvents` vs `DeviceImageLoadEvents` may differ for the same file | Side-loaded DLLs may be modified between write and load; compare both |
| Defender AV itself as initiator | `InitiatingProcessFileName == "MsMpEng.exe"` | Defender scanning or remediating triggers process/file events — not an attacker |
| Timestamped event vs. alert time | Alert may fire hours after the event if detection is delayed | Always check the event's `TimeGenerated`, not just the alert timestamp |

## Reusable classification logic

### LOLBin type

**Lean benign positive when:** the loaded DLL is a known, signed Microsoft or vendor
component; the parent process is a legitimate installer, update service, or management
tool (SCCM, Intune, GPO); the command line matches a known software deployment pattern;
the LOLBin execution has a 30-day baseline on this host with the same parent; no network
connections to external IPs; no file writes to user-writable paths.

**Escalate when:** the loaded DLL is unsigned, in a temp/user-writable path, or has a
suspicious name; the parent process is unusual (explorer.exe → cmd.exe → regsvr32.exe);
network connections go to external IPs (especially on non-standard ports); the command
line contains encoded content, URL references, or suspicious flags (`/s /u /i:http`);
no baseline exists for this LOLBin on this host; file writes to startup/persistence
locations follow.

### Defender exclusion tamper type

**Lean benign positive when:** the exclusion was set by a management tool (SCCM, Intune,
GPO) or a known software installer; the excluded path is a legitimate application directory;
the same exclusion appears across many devices simultaneously (policy deployment); the
initiating account is a domain admin or system account performing a documented change.

**Escalate when:** the exclusion was set by a user-context process or script; the excluded
path is `C:\Users\*`, `%TEMP%`, `%APPDATA%`, or another user-writable location; a process
subsequently ran from the excluded path; the exclusion targets a file extension commonly
abused (`.exe`, `.dll`, `.ps1`, `.bat`); the initiating process chain is suspicious
(powershell → Add-MpPreference); the change is isolated to a single device (not GPO).

> Exclusion alerts measure *configuration change*, not malware. The tamper is only meaningful
> if something exploits the gap it creates — always check what ran from the excluded path.
