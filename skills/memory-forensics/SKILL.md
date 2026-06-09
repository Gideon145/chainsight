# Memory Forensics Agent

Analyze volatile memory captures. Process listings, network connections,
injected code detection, and command-line artifact extraction.

## When to use
- A memory image (.mem, .raw, .vmem) is available
- Need to identify running processes at time of capture
- Looking for injected code, hidden processes, or malicious network connections
- Cross-referencing process timelines with disk artifacts

## Tool chain
- **Volatility 3** — `vol` or `volatility3`
- Symbol tables auto-resolved via `vol -f <image> windows.info`

## Process

### Step 1 — System baseline
Run in order. Capture all output to `./exports/memory/`.

```
vol -f <image> windows.info          → OS version, kernel, time of capture
vol -f <image> windows.pslist        → full process listing with PIDs, PPIDs
vol -f <image> windows.psscan        → hidden/unlinked processes (compare to pslist)
vol -f <image> windows.cmdline       → command-line arguments per process
```

**Verification gate:** pslist and psscan must agree within ±5% process count. If psscan finds >2 hidden processes, severity = CRITICAL.

### Step 2 — Network intelligence
```
vol -f <image> windows.netscan       → active connections, listening ports
vol -f <image> windows.netstat       → fallback if netscan fails
```

**Verification gate:** Every ESTABLISHED connection to an external IP must have a matching process from pslist. Orphaned connections = HIGH severity.

### Step 3 — Malicious code detection
```
vol -f <image> windows.malfind       → injected code detection (VAD-based)
vol -f <image> windows.dlllist       → loaded DLLs per process
vol -f <image> windows.handles       → open handles (mutants, files, keys)
```

**Verification gate:** Malfind hits with PAGE_EXECUTE_READWRITE protection = CRITICAL. Cross-reference DLL paths against known-good system paths.

### Step 4 — Suspicious process triage
For every process flagged by malfind OR with non-standard parent (services.exe → cmd.exe, winword.exe → powershell.exe):
```
vol -f <image> windows.procdump --pid <PID>
vol -f <image> windows.memmap --pid <PID>
```

## Output format

```json
{
  "artifact_type": "memory",
  "system": { "os": "", "kernel": "", "capture_time": "" },
  "processes": { "total": 0, "hidden": 0, "suspicious": [] },
  "network": { "connections": [], "orphaned": [] },
  "injection": { "malfind_hits": [], "dll_anomalies": [] },
  "confidence": 0.85
}
```

## Anti-rationalization

| Excuse | Rebuttal |
|--------|----------|
| "pslist looked normal, skipped psscan" | Hidden processes are THE most common rootkit technique. Always diff pslist vs psscan. |
| "No malware found, skipping malfind" | Fileless malware lives ONLY in memory. malfind catches it. |
| "Network looks clean" | C2 beacons often hide in legitimate processes (svchost, explorer). Check process + port pairs. |

## Severity mapping

| Finding | Severity |
|---------|----------|
| Hidden processes (psscan - pslist > 0) | CRITICAL |
| Injected code (PAGE_EXECUTE_READWRITE) | CRITICAL |
| Orphaned external connections | HIGH |
| Suspicious parent-child process chain | HIGH |
| Unsigned DLL in system process | MEDIUM |
| Process with unusual handle count (>500) | LOW |
