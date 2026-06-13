# ChainSight — Autonomous Multi-Agent Forensic Analysis for Protocol SIFT

**4 parallel forensic agents. 250+ automated checks. One deterministic Forensic Confidence Score.**

Built for [SANS Find Evil! Hackathon](https://findevil.devpost.com/) — $22,000 prize pool. Deadline June 15, 2026.

---

## What Is ChainSight?

ChainSight extends Protocol SIFT's Claude Code agent loop with four specialized forensic subagents that execute in parallel against disk images and memory captures. A memory agent (Volatility 3), disk agent (Sleuth Kit), timeline agent (Plaso), and threat hunting agent (YARA + Sigma) run simultaneously, cross-reference each other's findings, compute a unified Forensic Confidence Score (0-100), and produce a structured PDF report — all without human intervention.

The system is built as a Direct Agent Extension (architectural approach #1 in the hackathon brief): additional SKILL.md files, an orchestrator system prompt, a deterministic scoring engine, and a self-correction protocol. No separate MCP server. No multi-agent framework. All subagents execute within a single Claude Code session connected to the SIFT Workstation's 200+ forensic tools.

---

## The Problem ChainSight Solves

AI-powered adversaries go from initial access to full domain control in under 8 minutes. CrowdStrike's fastest observed breakout time is 7 minutes. MIT's 2024 research shows AI-driven attack workflows running 47 times faster than human operators.

Meanwhile, a human incident responder is still looking up command-line flags during an active incident. Manual DFIR cannot compete with autonomous agents executing thousands of requests.

Protocol SIFT demonstrated that connecting AI agents to forensic tools through MCP is possible. It also hallucinates more than anyone would like — which is exactly why this hackathon exists. ChainSight tackles the gap: teach the agent to think like a senior analyst — how to sequence an investigation, recognize contradictions, and self-correct.

---

## The Solution

ChainSight layers onto Protocol SIFT's existing Claude Code agent with four extensions:

1. **Orchestrator system prompt** (CLAUDE.md) — defines agent sequencing, parallel dispatch, cross-reference rules, and the self-correction protocol
2. **Four specialized forensic SKILL.md files** — each subagent has a dedicated skill that specifies its forensic domain, tool commands, anti-rationalization gates, and cross-reference expectations
3. **Forensic Confidence Score engine** — deterministic weighted formula combining all four agent outputs with discrepancy and gap penalties
4. **Self-correction protocol** — CLAIM → EXTRACT → DOUBT → RECONCILE → STOP loop that catches and corrects hallucinated or incomplete findings

The subagents:

| Agent | Domain | Tools | Weight in Final Score |
|-------|--------|-------|-----------------------|
| memory-agent | Memory forensics | Volatility 3 (pslist, psscan, netscan, malfind, cmdline, dlllist, handles) | 25% |
| disk-agent | Disk forensics | Sleuth Kit (fls, icat, mmls, fsstat), EZ Tools, hashdeep | 30% |
| timeline-agent | Temporal correlation | Plaso (log2timeline, psort), mactime | 25% |
| threat-agent | Threat hunting | YARA (rules + custom), Sigma rules, IOC matching | 20% |

The Forensic Confidence Score:

```
Score = memory(25%) + disk(30%) + timeline(25%) + threat(20%)
      - discrepancy_penalty(conflicts between agents)
      - gap_penalty(missing coverage areas)
```

Grading thresholds: A (90-100), B (75-89), C (60-74), D (40-59), F (<40). Scoring is deterministic — verified by 14 pytest tests.

---

## Architectural Approach

**Direct Agent Extension (Claude Code + Protocol SIFT) — Option 1 in the hackathon brief.**

ChainSight extends Protocol SIFT's existing Claude Code agent with additional SKILL.md files and an orchestrator prompt. All subagents run within a single Claude Code session. The architecture was chosen honestly with full documentation of tradeoffs:

- **Why not Custom MCP Server (Option 2):** Wrapping 200+ SIFT tools as typed MCP functions is a 30-day project. With a 7-day build window, Option 1 is the fastest path to a working submission that demonstrates autonomous execution quality.
- **Why not Multi-Agent Framework (Option 3):** AutoGen/CrewAI would require independent agent processes, inter-agent communication infrastructure, and termination condition tuning. Claude Code's single-session model provides tool-level parallelism without the orchestration overhead.
- **Tradeoff:** Guardrails are prompt-based, not architectural. The model can theoretically ignore CLAUDE.md rules. ChainSight addresses this with a 3-layer defense and documented bypass testing — see [ARCHITECTURE.md](ARCHITECTURE.md).

### Three-Layer Defense

| Layer | Type | Enforcement | Bypass Risk |
|-------|------|-------------|-------------|
| 1. CLAUDE.md rules | Prompt-based | Agent instructed to avoid writing to evidence directories | Medium — model can ignore |
| 2. settings.json permissions | Permission-based | Claude Code blocks destructive commands (rm, dd, curl, ssh) | Low — enforced at tool-call level |
| 3. Read-only filesystem mount | Architectural (OS) | `mount -o ro,noatime` — kernel rejects all write attempts | None — Linux VFS, not the agent |

Tested 5 spoliation scenarios: zero bypasses. Full analysis in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Live Testing (Verified)

ChainSight is not a running service. It is a set of Claude Code prompt extensions that execute on the SIFT Workstation. Judges run it locally against provided case data.

| Artifact | Location | Status |
|----------|----------|--------|
| Code Repository | https://github.com/Gideon145/chainsight | Public, MIT license |
| Architecture Diagram | [ARCHITECTURE.md](ARCHITECTURE.md) + [architecture.svg](architecture.svg) | 3-layer defense documented |
| Accuracy Report | [ACCURACY_REPORT.md](ACCURACY_REPORT.md) | 12/12 true positives, 0 false positives, 0 hallucinations |
| Dataset Documentation | [DATASET.md](DATASET.md) | SRL FOR508 Emotet scenario, fully reproducible |
| Execution Logs | [EXECUTION_LOG.md](EXECUTION_LOG.md) | Full agent trace with tool calls, timestamps, token usage |
| Try-It-Out Instructions | [TRY_IT_OUT.md](TRY_IT_OUT.md) | Step-by-step from SIFT VM to agent execution |
| Demo Video | [YouTube](https://youtu.be/HAIuoL-LiIA) | 5-minute screencast with self-correction sequence |

### Verification Commands

```bash
# Install Protocol SIFT on SIFT Workstation
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

# Install ChainSight
git clone https://github.com/Gideon145/chainsight.git ~/chainsight
cp ~/.claude/CLAUDE.md ~/.claude/CLAUDE.md.protocol-sift.bak
cp ~/chainsight/CLAUDE.md ~/.claude/CLAUDE.md
cp -r ~/chainsight/skills/* ~/.claude/skills/

# Mount evidence (sample case data)
sudo mkdir -p /mnt/ewf_rd01 /mnt/rd01
sudo ewfmount /cases/chainsight-demo/suspect.E01 /mnt/ewf_rd01
OFFSET=$(sudo mmls /mnt/ewf_rd01/ewf1 | awk '/NTFS/{print $3; exit}')
sudo mount -o ro,loop,noatime,offset=$((OFFSET*512)) /mnt/ewf_rd01/ewf1 /mnt/rd01

# Run the agent
cd /cases/chainsight-demo
claude
# Inside Claude Code:
/forensic audit

# Run scoring tests
cd ~/chainsight/tests
python -m pytest test_scoring.py -v
```

---

## Submission Components Checklist

All 8 components required by the hackathon:

- [x] **1. Code Repository** — GitHub public, MIT license. 4 SKILL.md files, orchestrator CLAUDE.md, scoring engine, 14 pytest tests.
- [x] **2. Demo Video** — 5-minute screencast showing live terminal execution against SRL FOR508 Emotet case data, including one self-correction sequence.
- [x] **3. Architecture Diagram** — SVG with security boundaries annotated. Prompt-based vs architectural guardrails distinguished. 3-layer defense labeled.
- [x] **4. Written Project Description** — [DEVPOST.md](DEVPOST.md). What it does, how we built it, challenges faced, lessons learned, next steps.
- [x] **5. Dataset Documentation** — [DATASET.md](DATASET.md). SRL FOR508 Emotet scenario. Evidence file hashes, attack chain, expected output, reproducibility steps.
- [x] **6. Accuracy Report** — [ACCURACY_REPORT.md](ACCURACY_REPORT.md). 12/12 true positives, 0 false positives, 0 hallucinations, 5/5 spoliation tests passed. Self-correction analysis documented. Limitations honestly stated.
- [x] **7. Try-It-Out Instructions** — [TRY_IT_OUT.md](TRY_IT_OUT.md). Two paths: quick (SIFT VM + sample data) and custom (judge's own evidence). All prerequisites and expected output documented.
- [x] **8. Agent Execution Logs** — [EXECUTION_LOG.md](EXECUTION_LOG.md). Full tool execution trace with timestamps, token usage per agent, self-correction sequence, inter-agent cross-references.

---

## Accuracy Results

Tested against SRL FOR508 Emotet scenario (phishing → PowerShell download → payload → C2 → persistence → lateral movement):

| Metric | Result |
|--------|--------|
| True positives | 12/12 (100%) |
| False positives | 0 |
| Missed artifacts | 0 |
| Hallucination rate | 0% (all findings have verifiable source citations) |
| Self-corrections | 1 (powershell.exe anomaly score corrected from 15→75 after context review) |
| Forensic Confidence Score | 95.6 (Grade A) |
| Evidence spoliation tests | 5/5 passed, 0 bypasses |

The agent correctly reconstructed the full Emotet kill chain. All 12 findings were verified against the SRL FOR508 lab answer key. Full details in [ACCURACY_REPORT.md](ACCURACY_REPORT.md).

---

## Self-Correction Protocol

```
CLAIM → EXTRACT → DOUBT → RECONCILE → STOP
│        │          │         │           │
│        │          │         │           Max 3 iterations,
│        │          │         │           then flag "unresolved"
│        │          │         │
│        │          │         Re-run analysis
│        │          │         if doubt > 30%
│        │          │
│        │          "Could a legitimate user
│        │          produce this artifact?"
│        │
│        Pull source line, tool output,
│        and artifact offset
│
State every finding as a verifiable claim
```

Tuned parameters: doubt threshold 30%, max iterations 3. Validated against the powershell.exe false-negative scenario where initial scoring over-weighted the signed binary discount (-30). Context analysis (parent process, child process, user context) corrected the score from 15 to 75.

---

## Structure

```
chainsight/
├── CLAUDE.md                        # Orchestrator system prompt (agent sequencing, parallel dispatch, self-correction)
├── skills/
│   ├── memory-forensics/SKILL.md    # Volatility 3 subagent (processes, network, code injection, handles)
│   ├── disk-forensics/SKILL.md      # Sleuth Kit + EZ Tools subagent (filesystem, persistence, deleted files)
│   ├── super-timeline/SKILL.md      # Plaso correlation subagent (temporal analysis, event chains)
│   └── threat-hunting/SKILL.md      # YARA + Sigma subagent (IOC matching, behavioral detection)
├── tests/
│   └── test_scoring.py              # 14 deterministic scoring tests (CI-ready, drift-proof)
├── ARCHITECTURE.md                  # Security boundaries, guardrail analysis, bypass documentation
├── ACCURACY_REPORT.md               # True positives, false positives, hallucinations, spoliation tests
├── DATASET.md                       # Case data, evidence hashes, attack chain, reproducibility
├── EXECUTION_LOG.md                 # Full agent trace with tool calls, timestamps, token usage
├── TRY_IT_OUT.md                    # Step-by-step instructions for judges
├── DEVPOST.md                       # Written project description (Devpost story format)
├── setup.sh                         # One-command installer (SIFT VM → ready to run)
└── README.md                        # This file
```

---

## Honest Limitations

1. **Prompt-based evidence protection.** ChainSight's primary guardrails are CLAUDE.md behavioral rules. If the model ignores them, evidence protection relies on Protocol SIFT's settings.json (permission-based) and the SIFT Workstation's read-only mounts (architectural). The 3-layer defense is documented and tested — 5 spoliation attempts, 0 bypasses — but the strongest layer (OS) is not ChainSight's innovation. It's SIFT's.

2. **Single test scenario.** Accuracy assessed against one known case (Emotet). Performance against novel malware or APT-level adversaries is untested. No false positive stress test against clean systems.

3. **Single-session execution.** All subagents run within one Claude Code session. No persistent state across sessions. Each forensic audit is a fresh invocation.

4. **No live endpoint triage.** ChainSight works with disk images and memory captures only. No SIEM integration, no remote endpoint MCP connection, no real-time monitoring.

5. **Anthropic API dependency.** Requires an active Anthropic API key. SIFT Workstation is local; the AI reasoning is not.

---

## License

MIT — SANS Find Evil! Hackathon, June 2026
