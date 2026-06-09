# FIND EVIL — Autonomous Incident Response for Protocol SIFT

**4 parallel forensic agents. 250+ checks. One Forensic Confidence Score.**

Built for the [SANS FIND EVIL! Hackathon](https://findevil.devpost.com/).

---

## Architecture: Direct Agent Extension

FIND EVIL extends Protocol SIFT's existing Claude Code agent loop with 4
specialized forensic subagents, a weighted confidence scoring engine, and a
self-correction protocol. This is **Option 1 (Direct Agent Extension)** in the
hackathon's supported architectural approaches.

```
Protocol SIFT (baseline)          FIND EVIL (this submission)
─────────────────────────         ─────────────────────────────
Claude Code + 5 SKILL.md          Claude Code + 9 SKILL.md
  files (reference)                 files (4 new forensic agents
                                    + orchestrator + scoring)
                                  ┌──────────────────────────┐
/forensic audit ─────────────────►│  ORCHESTRATOR            │
                                  │  Parallel agent dispatch  │
                                  │  Confidence Score engine  │
                                  │  Self-correction loop     │
                                  └────┬─────┬─────┬─────────┘
                                       │     │     │
                            ┌──────────┘     │     └──────────┐
                            ▼                ▼                ▼
                      memory-agent     disk-agent      timeline-agent
                      (Volatility 3)   (Sleuth Kit)    (Plaso)
                                       │
                                       ▼
                                  threat-agent
                                  (YARA + Sigma)
                                       │
                                       ▼
                                  ┌─────────────────────┐
                                  │  SYNTHESIZER         │
                                  │  Cross-reference      │
                                  │  Confidence Score     │
                                  │  PDF Report           │
                                  └─────────────────────┘
```

### Why Direct Agent Extension (not MCP)

| Approach | Pros | Cons |
|----------|------|------|
| **Direct Agent Extension (chosen)** | Fastest path to working submission. Leverages Protocol SIFT's existing tool permissions, audit logging, and evidence protection. | Guardrails are prompt-based, not architectural. Model can theoretically ignore read-only rules. |
| Custom MCP Server (not chosen) | Architectural enforcement — agent physically cannot run destructive commands. | Most work. Requires wrapping 200+ SIFT tools as typed functions. 7-day deadline makes this unrealistic. |

**We chose Option 1 with full awareness of the tradeoffs.** The security analysis
of what happens when the model ignores read-only rules is in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## What it does

Protocol SIFT gives Claude Code access to 200+ forensic tools. FIND EVIL makes
those tools work together as an autonomous incident response team — 4 specialized
subagents running in parallel, cross-referencing each other's findings, and
producing a single Forensic Confidence Score.

---

## Forensic Confidence Score (0-100)

```
Score = memory(25%) + disk(30%) + timeline(25%) + threat(20%)
      - discrepancy_penalty - gap_penalty
```

| Grade | Score | |
|-------|-------|-----|
| A | 90-100 | High-confidence, all sources correlated |
| B | 75-89 | Solid, minor discrepancies resolved |
| C | 60-74 | Useful but gaps or unresolved contradictions |
| D | 40-59 | Significant gaps, low confidence |
| F | <40 | Insufficient evidence |

Scoring math is **deterministic** — verified by 14 pytest tests.

---

## Self-correction protocol

```
CLAIM → EXTRACT → DOUBT → RECONCILE → STOP
State   Pull      "Could   Re-run      Max 3
finding source    a legit  analysis    iterations
        line      user      if doubt    then flag
                  produce   >30%        "unresolved"
                  this?"
```

---

## Structure

```
find-evil/
├── CLAUDE.md                        # Orchestrator system prompt
├── ARCHITECTURE.md                  # Security boundaries + guardrail analysis
├── skills/
│   ├── memory-forensics/SKILL.md    # Volatility 3 agent
│   ├── disk-forensics/SKILL.md      # Sleuth Kit + EZ Tools agent
│   ├── super-timeline/SKILL.md      # Plaso correlation agent
│   └── threat-hunting/SKILL.md      # YARA + Sigma agent
├── tests/
│   └── test_scoring.py              # 14 deterministic scoring tests
└── README.md
```

---

## Installation

```bash
# 1. Install Protocol SIFT
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

# 2. Install FIND EVIL (extends Protocol SIFT with 4 forensic agents)
git clone https://github.com/Gideon145/find-evil.git ~/find-evil
cp ~/.claude/CLAUDE.md ~/.claude/CLAUDE.md.protocol-sift.bak
cp ~/find-evil/CLAUDE.md ~/.claude/CLAUDE.md
cp -r ~/find-evil/skills/* ~/.claude/skills/
```

---

## Usage

```bash
cd /cases/<CASE>
claude

/forensic audit          # Full autonomous audit
/forensic memory         # Memory-only
/forensic disk           # Disk-only
```

---

## Known limitations (honestly documented)

1. **Prompt-based evidence protection** — relies on Claude Code respecting CLAUDE.md rules. Protocol SIFT's settings.json blocks destructive commands. We add no architectural enforcement beyond this. See [ARCHITECTURE.md](ARCHITECTURE.md) for bypass analysis.

2. **Not yet tested against ground truth** — scoring math is deterministic, but accuracy report against labeled data is pending before submission.

3. **Sequential within a single session** — subagents run in one Claude Code process, not independent AutoGen/CrewAI agents.

4. **No live endpoint triage** — works with disk/memory captures only. No SIEM/remote endpoint integration.

---

## License

MIT — SANS FIND EVIL! Hackathon, June 2026.
