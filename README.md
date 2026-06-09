# FIND EVIL — Autonomous IR Agent for Protocol SIFT

**4 parallel forensic agents. 250+ checks. One Forensic Confidence Score.**

Built for the [SANS FIND EVIL! Hackathon](https://findevil.devpost.com/).

---

## What it does

Protocol SIFT gives Claude Code access to 200+ forensic tools. FIND EVIL makes
those tools work together as an autonomous incident response team.

```
/forensic audit
    │
    ├─► memory-agent     (Volatility 3: processes, network, injection)
    ├─► disk-agent       (Sleuth Kit: MFT, USN, Prefetch, Registry, Events)
    ├─► timeline-agent   (Plaso: super-timeline + cross-reference rules)
    └─► threat-agent     (YARA + Sigma + IOC sweep + anomaly scoring)
            │
            ▼
    ┌─────────────────────────────┐
    │  SYNTHESIZER                │
    │  Forensic Confidence Score  │
    │  Attack chain reconstruction│
    │  PDF report generation      │
    └─────────────────────────────┘
```

---

## Architecture

### 4 forensic subagents with structured output

Each agent produces deterministic JSON with confidence scores. Agents
cross-reference each other's findings — no single agent's output is trusted
without corroboration.

### Forensic Confidence Score (0-100)

Weighted scoring across all 4 evidence sources:
- Memory: 25% | Disk: 30% | Timeline: 25% | Threat: 20%
- Discrepancy penalty: contradictions between agents lowers score
- Gap penalty: missing evidence types lowers score

### Self-correction protocol

CLAIM → EXTRACT → DOUBT → RECONCILE → STOP. Every finding is
adversarially reviewed. Max 3 re-run iterations before flagging as
"unresolved."

### Deterministic eval harness

pytest suite validates: scoring math, severity consistency, output format.
CI-ready.

---

## Structure

```
find-evil/
├── CLAUDE.md                        # Orchestrator system prompt
├── skills/
│   ├── memory-forensics/SKILL.md    # Volatility 3 agent
│   ├── disk-forensics/SKILL.md      # Sleuth Kit + EZ Tools agent
│   ├── super-timeline/SKILL.md      # Plaso correlation agent
│   └── threat-hunting/SKILL.md      # YARA + Sigma + IOC agent
├── tests/
│   └── test_scoring.py              # Deterministic scoring + format validation
├── iocs/                            # Place IOC files here
│   ├── hashes.txt
│   ├── ips.txt
│   ├── domains.txt
│   └── mutexes.txt
├── rules/                           # Place YARA rules here
│   ├── c2_beacons.yar
│   ├── ransomware.yar
│   ├── cred_theft.yar
│   ├── lolbins.yar
│   └── custom.yar
└── README.md
```

---

## Installation

Requires SANS SIFT Workstation + Protocol SIFT + Claude Code.

```bash
# 1. Install Protocol SIFT
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

# 2. Install FIND EVIL skills
git clone https://github.com/Gideon145/find-evil.git ~/find-evil
cp ~/find-evil/CLAUDE.md ~/.claude/CLAUDE.md
mkdir -p ~/.claude/skills
cp -r ~/find-evil/skills/* ~/.claude/skills/
```

---

## Usage

```bash
cd /cases/<CASE>
claude

# Run full autonomous audit
/forensic audit

# Or target specific evidence
/forensic memory   # Memory-only analysis
/forensic disk     # Disk-only analysis
```

---

## Why this beats the baseline

| Protocol SIFT (baseline) | FIND EVIL |
|--------------------------|-----------|
| One agent, sequential tool calls | 4 parallel subagents |
| Raw tool output, no synthesis | Structured JSON + Confidence Score |
| No cross-referencing | 6 correlation rules across evidence sources |
| No self-correction | Doubt-driven review with re-run loop |
| Manual PDF report | Auto-generated with evidence chain |
| No testing | pytest eval harness |

---

## License

MIT — built for the SANS FIND EVIL! Hackathon, June 2026.
