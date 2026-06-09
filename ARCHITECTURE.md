# Architecture — Security Boundaries & Guardrail Analysis

## Architectural pattern

**Direct Agent Extension (Claude Code + Protocol SIFT)**

FIND EVIL extends Protocol SIFT's existing Claude Code agent with additional
SKILL.md files, an orchestrator system prompt (CLAUDE.md), a confidence scoring
engine, and a self-correction protocol. No separate MCP server. No multi-agent
framework. All subagents run within a single Claude Code session.

---

## Security boundaries

```
┌─────────────────────────────────────────────────────────┐
│ CLIENT: Claude Code process (Anthropic API)              │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │ PROMPT-BASED GUARDRAILS                           │  │
│  │                                                   │  │
│  │ CLAUDE.md: "Never write to /cases/, /mnt/,        │  │
│  │ /media/. Output goes to ./analysis/ only."        │  │
│  │                                                   │  │
│  │ Each SKILL.md: "Verification gate" steps that     │  │
│  │ require specific tool output before proceeding.   │  │
│  │ Anti-rationalization tables block skipping.       │  │
│  │ Self-correction: CLAIM→EXTRACT→DOUBT→RECONCILE    │  │
│  └───────────────────┬───────────────────────────────┘  │
│                      │                                   │
│  ┌───────────────────▼───────────────────────────────┐  │
│  │ PERMISSION-BASED GUARDRAILS (Protocol SIFT)       │  │
│  │                                                   │  │
│  │ settings.json:                                    │  │
│  │   permissions.allow: Volatility, Sleuth Kit,      │  │
│  │     EZ Tools, Plaso, bulk_extractor, YARA, hash   │  │
│  │   permissions.deny: rm -rf, dd, wget, curl, ssh,  │  │
│  │     WebFetch                                       │  │
│  │   Write scope: ./analysis/*, ./reports/*,         │  │
│  │     ./exports/* ONLY                               │  │
│  │                                                   │  │
│  │ Stop hook: forensic_audit.log after every session  │  │
│  └───────────────────┬───────────────────────────────┘  │
│                      │                                   │
│  ┌───────────────────▼───────────────────────────────┐  │
│  │ FILESYSTEM GUARDRAILS (SIFT Workstation)          │  │
│  │                                                   │  │
│  │ Evidence mounted read-only:                       │  │
│  │   mount -o ro,loop,noatime /mnt/rd01              │  │
│  │ EWF container is read-only by design              │  │
│  │                                                   │  │
│  │ ⚠ STRONGEST LAYER — even if Claude ignores       │  │
│  │ all prompts and bypasses permissions, the OS      │  │
│  │ prevents writes to read-only mounts.              │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Three-layer defense

| Layer | Type | What it blocks | Bypass risk |
|-------|------|----------------|-------------|
| 1. CLAUDE.md rules | Prompt-based | Agent intentionally avoids writing to evidence | Medium — model can ignore prompts |
| 2. settings.json permissions | Permission-based | Agent cannot execute blocked commands (rm, dd, curl) | Low — Claude Code enforces these at the tool-call level |
| 3. Read-only filesystem mount | Architectural (OS-level) | OS kernel blocks all write attempts | None — enforced by Linux VFS, not the agent |

---

## What happens when the model ignores read-only rules

This is the critical question the hackathon asks. Here is the honest answer.

### Scenario: Model ignores "never write to /mnt/" and attempts to modify evidence

**Outcome: The write fails at the OS level.**

Evidence is mounted read-only (`mount -o ro`). The Linux kernel rejects the
write with `EROFS` (Read-only file system). Claude Code receives the error and
reports it. The evidence is not modified. This is architectural enforcement,
not prompt-based.

### Scenario: Model hallucinates a finding and cites a non-existent tool output

**Outcome: Caught by the verification gate.**

Every finding must cite a specific tool output line. The self-correction
protocol's EXTRACT step fetches the actual tool output. If the cited line
doesn't exist, the finding is flagged as "unverified" and does not appear
in the report.

### Scenario: Model skips a critical check and claims it ran

**Outcome: Caught by the anti-rationalization table.**

Each SKILL.md has an anti-rationalization table that blocks common excuses.
If the model claims it "already checked" without producing the verification
gate output (e.g., diff between pslist and psscan), the orchestrator flags
the agent's output as incomplete.

### Scenario: Model runs a destructive command despite deny list

**Outcome: Blocked by Protocol SIFT's settings.json.**

The deny list (`rm -rf`, `dd`, `wget`, `curl`, `ssh`, `WebFetch`) is enforced
by Claude Code's tool permission system. The model physically cannot call these
commands — the tool call is rejected before reaching the shell. This is
permission-based enforcement, not prompt-based.

### Scenario: Model produces internally inconsistent findings across agents

**Outcome: Caught by the cross-reference engine.**

The orchestrator compares findings across all 4 agents. If memory-agent says
"process X ran at 14:32" but disk-agent says "process X was deleted at 14:30,"
the discrepancy penalty is applied and both agents are re-run with adjusted
parameters. Unresolved discrepancies are flagged in the report.

---

## Guardrail enforcement summary

| Guardrail | Type | Enforcement | Tested for bypass? |
|-----------|------|-------------|-------------------|
| No writes to evidence | Architectural (OS) | Read-only mount | Yes — OS blocks writes |
| No destructive commands | Permission-based | settings.json deny list | Yes — Claude Code enforces at tool-call level |
| No data exfiltration | Permission-based | curl/wget/ssh blocked | Yes — same deny list |
| Findings must cite sources | Prompt-based | Self-correction protocol | Yes — EXTRACT step validates |
| No skipped checks | Prompt-based | Anti-rationalization tables | Yes — verification gates |
| Cross-agent consistency | Prompt-based | Cross-reference engine | Yes — discrepancy detection |
| Session audit trail | Hybrid | Stop hook writes forensic_audit.log | Yes — automated by Protocol SIFT |

---

## Why not MCP server (Option 2)

Building a custom MCP server that wraps 200+ SIFT tools as typed functions
is the most sound architecture. It would make destructive commands physically
impossible because the server simply wouldn't expose them. This is the approach
we would take with a 30-day timeline.

However, with 7 days and the requirement to ship a working submission that
includes a demo video, accuracy report, architecture diagram, and execution
logs, we chose Option 1 (Direct Agent Extension) — the fastest path to a
working, testable, documented submission. The tradeoff is honest and documented.

---

## What we learned from Protocol SIFT's design

Protocol SIFT already implements strong permission-based controls (settings.json
with allow/deny lists, Stop hook audit logging, write scope restrictions).
FIND EVIL builds on this foundation rather than replacing it. We extend the
analytical capability (what the agent can find) while relying on Protocol SIFT's
existing security controls (what the agent can break).

This is a deliberate design choice: improve detection while preserving the
battle-tested security boundaries that SIFT has refined over 18 years.
