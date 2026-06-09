# Disk Forensics Agent

Analyze filesystem artifacts from disk images. Timeline construction,
file recovery, and Windows artifact parsing (MFT, USN Journal, Prefetch,
Amcache, Registry, Event Logs).

## When to use
- A disk image (.E01, .img, .dd, .raw) is mounted
- Need file system timeline or deleted file recovery
- Looking for persistence mechanisms, execution evidence, or file tampering

## Tool chain
- **Sleuth Kit (TSK)** — `fls`, `icat`, `mmls`, `mactime`, `tsk_recover`
- **EZ Tools** — `MFTECmd`, `PECmd`, `AmcacheParser`, `EvtxECmd`, `RECmd`
- **Plaso** — `log2timeline.py`, `psort.py` (delegated to timeline-agent)

## Process

### Step 1 — Partition layout
```
mmls <image>                        → partition table
```
Mount the largest NTFS partition read-only.

### Step 2 — MFT + USN Journal
```
MFTECmd -f /mnt/rd01/\$MFT --csv ./exports/disk/
MFTECmd -f /mnt/rd01/\$UsnJrnl:\$J --csv ./exports/disk/
```

**Verification gate:** MFT entry count must be >100. Zero entries = wrong partition offset. USN Journal must contain delete/rename events — if empty, evidence may have been tampered with.

### Step 3 — Execution artifacts
```
PECmd -f /mnt/rd01/Windows/Prefetch --csv ./exports/disk/
AmcacheParser -f /mnt/rd01/Windows/AppCompat/Programs/Amcache.hve --csv ./exports/disk/
```

**Verification gate:** Every executable in Prefetch must have a matching MFT entry. Missing MFT = file was deleted (recovery attempt via `tsk_recover`).

### Step 4 — Persistence + Registry
```
RECmd --bn ./BatchExamples/Kroll_Batch.reb --nl --csv ./exports/disk/
```
Key hives to parse: SYSTEM, SOFTWARE, NTUSER.DAT for each user.

**Verification gate:** Every Run key entry must be cross-referenced with Prefetch. If a persistence entry exists but Prefetch shows zero executions = dormant persistence.

### Step 5 — Event Logs
```
EvtxECmd -f /mnt/rd01/Windows/System32/winevt/Logs/ --csv ./exports/disk/
```
Focus on: Security (4624/4625 logons), System (7045 new services), PowerShell (4104 script blocks).

### Step 6 — Deleted file recovery
```
tsk_recover /mnt/rd01 ./exports/disk/recovered/
```

## Output format

```json
{
  "artifact_type": "disk",
  "filesystem": { "mft_entries": 0, "usn_deletes": 0 },
  "execution": { "prefetch_entries": [], "amcache_entries": [], "deleted_executables": [] },
  "persistence": { "run_keys": [], "services": [], "scheduled_tasks": [] },
  "events": { "logons": [], "service_installs": [], "ps_scripts": [] },
  "confidence": 0.90
}
```

## Anti-rationalization

| Excuse | Rebuttal |
|--------|----------|
| "Prefetch looks normal" | Prefetch shows FIRST and LAST execution timestamps. A tool run once and deleted still leaves a trace. Always parse. |
| "No event logs found" | Event log clearing is a T1064 technique. If Security.evtx is small or empty, flag it as evidence tampering. |
| "Registry too complex, skipping" | Run keys and services are 2 keys. Parse them. They take 30 seconds. |

## Severity mapping

| Finding | Severity |
|---------|----------|
| Cleared event logs (Security.evtx < 1MB with >7 days uptime) | CRITICAL |
| Suspicious service install (Event 7045 + unsigned binary) | CRITICAL |
| Deleted executable with Prefetch evidence of execution | HIGH |
| Run key pointing to AppData/Temp path | HIGH |
| Scheduled task executing PowerShell with encoded command | HIGH |
| Amcache entry with no Prefetch (potential timestamp manipulation) | MEDIUM |
