# ChainSight — Devpost Project Description

## Inspiration

I audit smart contracts for a living. Last month I found a Medium-severity bug in a DeFi protocol on Sherlock — it took me hours of manual analysis on a 900-line contract. After submitting, one thought stuck: attackers don't wait hours anymore.

Anthropic's report on GTG-1002 confirmed it — state-sponsored operators using AI agents at request rates "physically impossible" for humans. CrowdStrike clocked breakout time at 7 minutes. MIT found AI attack workflows running 47x faster than human operators.

The offensive side is automated. The defensive side is still typing command-line flags during an active incident. ChainSight is my attempt to apply adversarial thinking — the same mindset I use to find bugs in code — to the problem of finding attackers in evidence.

---

## What it does

ChainSight is a Python orchestrator that dispatches 4 forensic agents against disk images and memory captures. Each agent specializes in one evidence type, produces structured JSON output with confidence scores, and cross-references findings against the other three agents.

If the timeline agent detects files created within milliseconds of each other and the disk agent finds an encoded PowerShell command and a registry Run key, the threat hunting agent correlates them into a complete Emotet kill chain. Every finding is traceable to the exact tool command that produced it.

The result is a single **Forensic Confidence Score (0-100)** — graded A through F — with a deterministic formula validated by 14 pytest tests. Same evidence, same score, every time.

In live testing against planted Emotet artifacts: 7 findings (3 CRITICAL, 3 HIGH, 1 MEDIUM), 85.5 Forensic Confidence Score (Grade B), full attack chain reconstructed. The demo video shows the entire 5-minute run: evidence creation → 4-agent dispatch → cross-reference → scoring → report.

---

## How we built it

**Architecture: Pure Python orchestrator with rule-based detection.** Zero API keys. Zero external services. Zero Claude Code dependency.

The orchestrator (`orchestrator.py`) runs 4 detection stages:

| Stage | Agent | Method |
|-------|-------|--------|
| 1. Collect | Disk | `find`, `cat`, `strings` — reads suspicious files from mounted evidence |
| 2. Score | Rule Engine | Regex pattern matching: base64 PowerShell → CRITICAL, Run key persistence → CRITICAL, IP:port beacon → HIGH |
| 3. Cross-Reference | Timeline | `find -printf` temporal analysis: files created within 1 second → automated deployment |
| 4. Hunt | Threat | Cross-agent correlation: phishing + persistence + C2 confirmed → full kill chain |

**Why rule-based, not AI.** We started with Google Gemini for semantic analysis. Hit rate limits on the free tier. Switched to Claude Code — hit credit limits. Realized the planted artifacts (encoded PowerShell, reg key, C2 config) don't need AI to detect. Regex is faster, deterministic, and costs nothing. The hackathon judges explicitly asked for architectures where "the agent physically cannot run destructive commands" — our orchestrator only runs `find`, `cat`, and `strings`. It cannot modify evidence.

**Security: architectural enforcement.** Evidence is mounted read-only (`mount -o ro,loop`). The orchestrator uses Python's `subprocess.run` with list-form commands — no shell, no injection possible. Tools are called by exact name (`find`, `cat`, `strings`) — no arbitrary command execution. Documented in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Challenges we ran into

**API rate limits killed two approaches.** Gemini 2.5 Flash Lite free tier: 20 requests/day. Gemini 2.0 Flash: 0 requests/day (quota exhausted). Claude Code: credit balance too low. Each failure forced us toward a better architecture. The final version needs no API at all — pure Python on the SIFT Workstation.

**Permission hell on read-only mounts.** Evidence files created as root, filesystem remounted read-only, then the orchestrator (running as `sansforensics`) couldn't read them. Fixed by adding `sudo chmod -R a+r` before the final `mount -o ro`. Took 6 deployment attempts to get right.

**Making scoring deterministic under missing data.** Without a memory image, 25% of the score weight was lost. The original formula would always produce F-grade results on disk-only cases. Redistributed weights (disk 40%, timeline 30%, threat 30%) when memory is absent, with gap penalties removed. Same formula handles both cases transparently.

**Domain gap.** I don't know Windows forensics. Every detection rule was built by reading SIFT tool documentation, studying the FOR508 scenario, and pattern-matching from audit workflows I already understand. The rules caught all planted artifacts on the first successful run.

---

## Accomplishments that we're proud of

**Zero-cost, zero-dependency architecture.** No API keys. No credits. No external services. The entire system runs on a stock SIFT Workstation with Python 3. Judges can clone the repo and run it in 3 commands. No account setup, no billing, no rate limits.

**Deterministic, verifiable results.** Same evidence → same findings → same score. Every time. Validated by 14 pytest tests. Judges can reproduce any run and get identical output. No AI hallucination possible because there's no AI — just regex rules with clearly documented detection logic.

**Full attack chain reconstruction.** The threat agent doesn't just list findings — it correlates across agents. Phishing (invoice.js) + persistence (Run key) + C2 (beacon config) = confirmed Emotet kill chain. This is what a senior analyst does manually. The orchestrator does it in 5 seconds.

**Honest limitations.** We document exactly what happens when the model isn't there to help — the rule engine catches known patterns but won't generalize to novel attacks. That's the tradeoff. For known malware families, it's faster and more reliable than an LLM. For zero-days, you still need a human.

---

## What we learned

1. **The simplest architecture wins under time pressure.** Started with Claude Code skills. Pivoted to Gemini API. Ended with pure Python. Each pivot removed a dependency. The final version has none.

2. **Regex beats AI for known patterns.** An encoded PowerShell command is an encoded PowerShell command. You don't need a language model to find `powershell.*-enc`. The rules are 10 lines of Python each. They run instantly. They never hallucinate.

3. **Cross-referencing is force multiplication.** Individual agents find individual artifacts. The threat agent connects them into an attack chain. That's the value — not any single detection rule, but the correlation between them.

4. **You can build in a domain you don't know.** My background is DeFi, not DFIR. But the pattern is the same: identify what attackers leave behind, build structured checks for each artifact, cross-reference to catch contradictions. The domain changes. The methodology doesn't.

5. **Read-only mounts are the real security.** Not prompt engineering. Not API keys. The Linux kernel rejecting write attempts to a read-only filesystem — that's what actually protects evidence.

---

## What's next for ChainSight

- **Add more detection rules** — ransomware (Ryuk/Conti), APT (APT29), insider threat patterns
- **False positive stress test** against clean disk images to measure baseline noise
- **Memory forensics integration** — wire Volatility 3 into the orchestrator for full disk+memory analysis
- **Build the typed MCP server** — wrap SIFT tools as structured functions so the agent physically cannot run destructive commands (the architecture judges explicitly preferred)
- **Add live endpoint triage** via MCP-connected SIEM for real-time incident response
- **Open-source the eval harness** so the community can benchmark forensic agent accuracy
