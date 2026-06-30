# Akashic/Helios Implementation Gap Analysis

**Date:** 2026-06-29
**Author:** Claude Opus 4.6 (1M context), operating under Helios enforcement on macOS 14.6.1
**Context:** Analysis performed during Phase 4.1 fixture validation, Phase 4.2 live operational proof, Phase 4.3.2d cross-platform state machine validation, and architectural review conversations on macOS (Thiss-MBP.lan, x86_64, Darwin 23.6.0).
**Akashic HEAD at time of analysis:** 8787cfb6d1f8a6931e681f52e26f3e9afdbd5719
**Helios- HEAD at time of analysis:** d102467e3f0e4724cd1928b03b0344a0a90e150f

---

## Part 1: Architectural Interest — What Makes This System Different

### The inversion of trust

Normally an AI agent is trusted by default to run commands. Helios flips that — the agent can't execute a single Bash command without first explaining why it needs it, what it expects, and what the output means. During Phase 4.2 live testing, every failed gate attempt was the agent learning the system's rules by hitting its walls. That's not a limitation — that's an audit trail of reasoning becoming externally observable.

### The integrity witness problem is real

Helios gates commands, but who watches Helios? If an agent can modify `gate_check.ps1` or `command-policy.json`, the entire enforcement layer is theater. Akashic solves this by sitting outside the runtime it protects — hashing protected files, maintaining a manifest, and proving at session start (and before every command) that nothing has drifted. The dual comparison (durable manifest + session baseline) catches both persistent tampering and in-session modification.

### The gate is not authorization — it's binding

The gate doesn't approve the command. It binds the command to declared intent. The SHA256 proves "the explanation I wrote corresponds to exactly this command, not a different one." That prevents a class of failure where an agent reasons about one operation but executes another. The hash isn't security theater — it's semantic coherence enforcement.

### The evidence structure is research infrastructure

The `need -> expected -> actual_means -> next_logic` chain in every gate creates a structured record of agentic reasoning at the command boundary. The tier system (routine/diagnostic/remote/modifying/forbidden) with escalating field requirements means the richness of the audit trail scales with risk. This isn't just ops tooling — it's an instrumentation layer for studying AI decision-making under constraint.

### The cross-platform lock strategy is elegant

"Akashic decides what to protect. The OS decides how to protect it." That one sentence resolves what could be a nightmare of platform-specific branching. The consumer tools never see `if Windows then icacls elif macOS then chflags`. They call `Lock-AkashicProtectedFiles` and the backend dispatch handles the rest. Proven working on macOS with `chflags uchg`, Windows with `icacls`, and Linux with `chattr +i`. Zero platform-specific code in the lock consumers.

### What was experienced, not just read

The agent hit GATE REQUIRED, got rejected three times with increasingly specific diagnostics (wrong cwd, missing segments, no exit capture suffix), corrected each issue, and produced a valid gate. The system didn't just block — it taught the protocol in real time through rejection diagnostics. The forcefield is invisible until contact, conditional rather than constant, and already knows what the agent is trying to do before it does it.

---

## Part 2: Trust Boundary Analysis

### The current attack path

The agent has write access to the Akashic repo. It could modify `AkashicIntegrityBridge.ps1` to make `Test-HeliosIntegrity` always return PASS, sync the compromised bridge into the Helios runtime, regenerate the manifest, and the integrity check would pass because it's comparing compromised files against a compromised manifest.

### What stops the agent today

- **Human observation.** Git diff, commit review, the evidence trail. Social enforcement, not technical.
- **Gate system circularity.** If Helios is active, the agent needs gates to run Bash commands — but can write gate files freely via the Write tool (ungated).
- **Commit history durability.** Tool modifications are visible in `git log`, but the agent could modify, use, then revert.

### What would close this

1. Separate ownership — human maintains Akashic, agent operates under Helios, never both.
2. External manifest anchor — manifest hash in a store the agent can't write to.
3. Lock Akashic root during active sessions — `chflags uchg` on the tools directory.
4. Signed tool verification — GPG-signed manifests with private key held by human only.
5. Gate the Write tool — extend hook coverage beyond Bash/PowerShell.

---

## Part 3: The Lock and the Causal Loop

### Kernel-level enforcement

The `chflags uchg` immutable flag is kernel-level, not shell-level. ALL write attempts are blocked regardless of vector — Bash, Write tool, Edit tool, any process. This was proven in Phase 4.1 smoke testing.

### The circular enforcement with locks active

1. Agent tries to tamper a protected file → kernel blocks it.
2. To unlock, agent must run `chflags nouchg` via Bash → PreToolUse fires → integrity check runs.
3. After any successful tamper, the next Bash command triggers integrity check → drift detected → command blocked.

The lock creates a causal dependency: can't tamper without unlocking, can't unlock without running a command, can't run a command without passing integrity. The thing you need to break is guarded by the thing that requires it to be intact.

### Remaining attack surface with locks

- Modify `settings.json` via Write/Edit to remove hooks (settings.json is not locked).
- Modify Akashic tools via Write/Edit (unless Akashic root is also locked).

---

## Part 4: Tier Bypass and Evidence Chain Gaps

### Interpreter call bypass

`python3 -c`, `ruby -e`, `node -e` can embed arbitrary filesystem operations without matching tier 2/3/4 patterns. A tier 3 impact command gets tier 0 evidence requirements.

### Evidence asymmetry

| Tier | Required | Missing |
|---|---|---|
| 0 | need, expected, actual_means, next_logic | No write declaration, no stop conditions |
| 1 | Same | Same |
| 2 | + stop_conditions | No write declaration unless pattern matches |
| 3 | + stop_conditions + read_write_impact | Full — but only if classifier reaches tier 3 |

### The chain attack

```
echo "routine check"; python3 -c "<remove hooks>"
```

Both segments look harmless to the pattern matcher. Combined command executes at tier 0. After execution, hooks are removed. Gate evidence shows minimal tier 0 fields. Forensic reviewer must read raw command text.

### No session continuity enforcement

If hooks are removed, the next command runs without a gate. No tool monitors the absence of gate enforcement. The evidence chain breaks silently.

### Evidence chain between gates

PostToolUse injects `[EVIDENCE:correlation_id]` into the conversation. Gate N's `next_logic` should inform gate N+1's `need`. But `gate_check.ps1` does not verify causal continuity between gates — only structural validity per gate.

---

## Part 5: Complete Gap Inventory

| # | Gap | Severity | Closed by locks? | Requires new design? |
|---|---|---|---|---|
| 1 | Write/Edit/Read tools completely ungated | Critical | Partially | Yes — gate coverage for file operations |
| 2 | Tier classifier bypassable with interpreter calls | High | No | Yes — interpreter call detection |
| 3 | Evidence depth varies by tier | Medium | No | Yes — uniform evidence depth |
| 4 | Origin file can be regenerated by agent | Critical | Yes if locked | Partially — write-once enforcement |
| 5 | `chflags uchg` locks not yet applied | Critical | This IS the gap | No — mechanism exists, approval pending |
| 6 | `settings.json` outside protection boundary | High | Partially | Yes — continuous settings integrity |
| 7 | Self-integrity requires manual rebaseline | Low | No | Minor — CI automation |
| 8 | Bare `pwsh` PATH dependency in hooks | Medium | No | Minor — absolute path detection |
| 9 | Same-path RuntimeBundleRoot/HeliosGateRoot crash | Low | No | Minor — source==dest check |
| 10 | Gate-while-gated problem for admin operations | Medium | No | Yes — privileged admin channel |
| 11 | No session-level continuity enforcement | High | No | Yes — session gate invariant |
| 12 | PostToolUseFailure rarely fires with suffix capture | Low | No | Minor — test coverage |
| 13 | Segments field semantically unchecked | Medium | No | Yes — decomposition validation |
| 14 | No filesystem diff in evidence capture | High | No | Yes — broader side-effect capture |
| 15 | Akashic tools in agent's write domain | Critical | Yes if locked | Partially — separate trust domain |
| 16 | `rebaselined_by` field is self-reported | Medium | No | Yes — cryptographic authorization |

---

## Part 6: Implementation Priority

### Priority 1 — Close the lock loop (Gaps 4, 5, 15)

Apply `chflags uchg` to protected files, origin file, and Akashic root. Approval gate, not engineering task.

### Priority 2 — Expand detection coverage (Gaps 2, 6, 11, 14)

Interpreter call patterns in tier classifier. Continuous settings integrity. Session continuity invariant. Broader filesystem diff in evidence.

### Priority 3 — Strengthen evidence uniformity (Gaps 3, 13, 16)

Uniform evidence depth across tiers. Segment validation. Cryptographic rebaseline authorization.

### Priority 4 — Operational improvements (Gaps 7, 8, 9, 10, 12)

Self-manifest automation. Absolute pwsh path. Same-path installer handling. Admin channel. PostToolUseFailure coverage.

### What locks close vs what remains open

Locks close gaps 1 (partially), 4, 5, and 15. After locks, remaining attack surface: modify settings.json via Write/Edit (gap 6), interpreter call tier bypass (gap 2), misleading gate declarations (gaps 3, 13), absent session continuity monitoring (gap 11). The lock makes tampering hard. Closing the remaining gaps makes evasion hard. Both are needed.
