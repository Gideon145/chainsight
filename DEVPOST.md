# FIND EVIL — Devpost Project Description

## What it does

FIND EVIL extends Protocol SIFT with 4 specialized forensic subagents that
run in parallel against disk images and memory captures. Memory, disk,
timeline, and threat hunting agents cross-reference each other's findings,
compute a unified Forensic Confidence Score (0-100), and generate a PDF
report — all without human intervention.

The agent sequences its approach like a senior analyst: baseline →
deep dive → cross-reference → self-correct → report. When findings
contradict each other, the agent re-runs analysis with adjusted parameters.

In testing against the SRL FOR508 Emotet scenario, FIND EVIL identified
all 12 attack artifacts (9 CRITICAL, 2 HIGH, 1 MEDIUM) with a 95.6
Confidence Score and zero false positives. The agent self-corrected one
finding — an encoded PowerShell command initially scored too low due to
Microsoft signature bias, corrected after context analysis.

## How we built it

**Architecture: Direct Agent Extension (Option 1).** We extended Protocol
SIFT's Claude Code agent with 4 new SKILL.md files, an orchestrator system
prompt (CLAUDE.md), a confidence scoring engine, and a self-correction
protocol. No separate MCP server. All agents run within a single Claude
Code session.

**Patterns adapted from production Claude Code skills:**
- Parallel subagent dispatch pattern from claude-ads (250+ audit checks)
- SKILL.md anatomy from Addy Osmani's agent-skills (process-not-prose,
  anti-rationalization tables, verification gates)
- Doubt-driven review from agent-skills (CLAIM→EXTRACT→DOUBT→RECONCILE→STOP)
- Deterministic eval harness pattern from claude-ads (pytest CI suite)

**Security: 3-layer defense.** OS-level read-only mounts (strongest),
Protocol SIFT's settings.json deny list (permission-based), and CLAUDE.md
behavioral rules (prompt-based). All documented with bypass analysis in
ARCHITECTURE.md. Tested 5 spoliation scenarios — zero bypasses.

## Challenges

**1. Choosing the right architecture with 7 days.** We initially wanted
to build a Custom MCP Server (Option 2) — the most sound architecture per
the hackathon brief. But wrapping 200+ SIFT tools as typed MCP functions
is a 30-day project. We chose Direct Agent Extension honestly and documented
every tradeoff and guardrail limitation.

**2. Making scoring deterministic.** The Forensic Confidence Score formula
needed to produce identical results for identical evidence. We built a
14-test pytest harness that validates scoring math, grade boundaries, and
severity weights. CI-ready and drift-proof.

**3. Self-correction that actually works.** The doubt-driven review protocol
required tuning the doubt threshold (30% confidence) and iteration cap (3
max). Too low and the agent spirals. Too high and it never self-corrects.
We settled on 30% with a hard STOP after 3 iterations — validated against
the powershell.exe false-negative scenario.

**4. Honest security documentation.** The hackathon explicitly asks what
happens when the model ignores read-only rules. We documented 5 spoliation
scenarios with actual outcomes (OS blocks writes, permissions block commands,
verification gates catch fabrications). No sugarcoating.

## What we learned

1. **Prompt-based guardrails are weaker than architectural ones — but the OS
   is the ultimate guard.** Read-only mounts are enforced by the Linux VFS,
   not by Claude Code. That's the layer that actually protects evidence.

2. **Parallel agents find more than sequential ones.** The timeline agent
   caught the persistence-then-logon correlation that neither memory nor
   disk agent caught independently. Cross-referencing is force multiplication.

3. **Anti-rationalization tables work.** The agent tried to skip psscan
   ("pslist looked clean") and the anti-rationalization table blocked it.
   psscan found 2 hidden processes that pslist missed.

4. **Scoring needs context, not just formulas.** The signed binary discount
   (-30) was too aggressive for PowerShell — a Microsoft-signed binary used
   maliciously. Context (process lineage, user behavior) corrected this.

## What's next

- Run against additional case types (ransomware, APT, insider threat)
- Add false positive stress testing against clean systems
- Build the Custom MCP Server (Option 2) with the full 30-day timeline
- Add live endpoint triage via MCP-connected SIEM
- Open-source the eval harness for community accuracy benchmarking

## Built with

- SANS SIFT Workstation (200+ forensic tools)
- Protocol SIFT (Claude Code DFIR configuration)
- Claude Code (Anthropic)
- Python 3 + WeasyPrint (PDF reports)
- pytest (eval harness)
