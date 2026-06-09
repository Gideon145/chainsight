# Super-Timeline Agent

Build and analyze a unified super-timeline from disk + memory artifacts.
Cross-reference events across sources, flag temporal inconsistencies,
and correlate suspicious activity chains.

## When to use
- Both disk and memory evidence are available
- Need to establish attack timeline
- Looking for temporal patterns (beaconing intervals, dwell time)
- Cross-referencing findings from disk-agent and memory-agent

## Tool chain
- **Plaso** — `log2timeline.py`, `psort.py`, `pinfo.py`

## Process

### Step 1 — Build super-timeline
```
log2timeline.py --storage-file ./exports/timeline/super.plaso /mnt/rd01
log2timeline.py --storage-file ./exports/timeline/memory.plaso --partition 1 <memory_image>
```

### Step 2 — Merge + filter
```
psort.py -o l2tcsv ./exports/timeline/super.plaso ./exports/timeline/memory.plaso \
  "date > '2026-01-01'" > ./exports/timeline/merged.csv
```

**Verification gate:** Merged timeline must contain events from BOTH disk and memory sources. Single-source timeline = missing evidence.

### Step 3 — Temporal clustering
Group events into 30-second windows. Within each window:
- Count unique processes involved
- Tag execution chains (parent → child → grandchild)
- Flag gaps >1 hour (potential anti-forensics)

### Step 4 — Cross-reference attacks (6 correlation rules)

| Rule | Sources | Condition | Severity |
|------|---------|-----------|----------|
| **Process-created-then-deleted** | MFT + Prefetch + pslist | Prefetch has execution, MFT shows deleted, pslist absent | HIGH |
| **Network-after-injection** | netscan + malfind | Network connection within 60s of malfind hit | CRITICAL |
| **Persistence-then-logon** | Registry + Security.evtx | Run key written within 60s before new logon (4624) | CRITICAL |
| **Hidden-process-beacon** | psscan - pslist + netscan | Hidden process with repeating outbound connections | CRITICAL |
| **Timeline-gap** | super-timeline | >1 hour with zero events on a system known to be active | HIGH |
| **Tool-transfer-via-browser** | MFT + Prefetch | Browser Downloads folder → executable within 60s | HIGH |

### Step 5 — Attack chain reconstruction
For each CRITICAL finding cluster, build:
```
[Initial Access] → [Execution] → [Persistence] → [C2 Beacon] → [Lateral Movement]
     │                 │               │               │               │
  Timestamp         Timestamp       Timestamp       Timestamp       Timestamp
  Source:           Source:         Source:         Source:         Source:
  Security.4625     Prefetch        Registry        netscan         Security.4648
```

## Output format

```json
{
  "artifact_type": "timeline",
  "total_events": 0,
  "time_range": { "start": "", "end": "" },
  "clusters": [
    {
      "window": { "start": "", "end": "" },
      "events": [],
      "processes": [],
      "attack_chain_stage": "execution",
      "confidence": 0.92
    }
  ],
  "gaps": [],
  "confidence": 0.88
}
```

## Anti-rationalization

| Excuse | Rebuttal |
|--------|----------|
| "Timeline is too big to process" | Filter to suspicious hours only. 200K events in a 2-hour window = something happened. |
| "Clusters are unclear" | Reduce window size from 60s to 30s. If clusters are still unclear, flag as LOW confidence. |
| "No attack chain found" | An isolated finding is still a finding. But search harder — most attacks leave 2+ traces. |

## Severity mapping

| Finding | Severity |
|---------|----------|
| 2+ correlation rules triggered in same window | CRITICAL |
| Network-after-injection correlation | CRITICAL |
| Persistence-then-logon correlation | CRITICAL |
| Hidden-process-beacon correlation | CRITICAL |
| Timeline gap >1 hour on active system | HIGH |
| Process-created-then-deleted | HIGH |
| Single correlation rule triggered | MEDIUM |
