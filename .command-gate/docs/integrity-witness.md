# Helios Integrity Witness

## Architecture

Three layers, each with a distinct role:

| Layer | Role | Status |
|---|---|---|
| **TCE** (TerminalContextExporter) | Local integrity witness concept. Design lineage and reference implementation for envelope hashing, snapshot comparison, and evidence writing. | Reference/lineage |
| **Helios** (command gate) | Runtime command enforcement. Gates Bash/PowerShell tool uses via PreToolUse/PostToolUse hooks. Vendors a TCE-style witness bridge for integrity verification. | Active runtime |
| **helios-lock** | Filesystem prevention. OS-native locks (icacls/chattr/chflags/chmod) that prevent modification of protected files between integrity checks. | Phase 4+ (not yet implemented) |

Helios owns the command-gate runtime. TerminalContextExporter remains reference lineage for the witness design. The vendored bridge at `hooks/lib/HeliosIntegrityBridge.ps1` is the only TCE-derived artifact in the active hook path. helios-lock will close the gap between detection and prevention.

## Current Detection Model

The integrity witness provides **detection-on-next-shell-action**, not prevention:

1. A model (or external actor) modifies a protected file.
2. The modification is not blocked at mutation time.
3. On the next Bash or PowerShell tool use, `helios_pretooluse.ps1` hashes all protected files.
4. Hash mismatch against the durable manifest triggers INTEGRITY_FAILURE and deny.
5. The command that would have executed against tampered policy is never run.

Direct file-edit tools (Edit, Write, NotebookEdit) do not trigger shell hooks. A protected file can be modified by these tools, and the modification is only detected when the next shell command fires. Phase 4 helios-lock addresses this gap with filesystem-level prevention.

## Envelope Model

### Runtime Protected Envelope

Files loaded by the active hook path. Must not change during gated execution:

| Relative Path | Loaded By | Role |
|---|---|---|
| `hooks/helios_pretooluse.ps1` | settings.json PreToolUse | Front controller entry point |
| `hooks/gate_check.ps1` | helios_pretooluse.ps1 (dot-sourced) | Gate validation logic |
| `hooks/evidence_capture.ps1` | settings.json PostToolUse/Failure | Post-command evidence capture |
| `hooks/tier_classifier.ps1` | helios_pretooluse.ps1 (dot-sourced) | Tier classification |
| `hooks/lib/HeliosIntegrityBridge.ps1` | helios_pretooluse.ps1, evidence_capture.ps1 (dot-sourced) | Vendored TCE witness bridge |
| `policy/command-policy.json` | tier_classifier.ps1, gate_check.ps1 | Tier patterns and gate policy |
| `templates/operating-catalog.json` | tier_classifier.ps1 (if present) | Tier override catalog |

### Durable Trust Anchors

| File | Role |
|---|---|
| `manifest/helios-envelope.json` | SHA256 hash registry for all protected files |
| `manifest/helios-envelope.sha256` | SHA256 of the manifest JSON (sidecar avoids self-hash) |

The manifest is the root of trust. It is valid only if created by a human-approved rebaseline step and has not drifted since. The sidecar is verified before the manifest is parsed.

### External Control-Plane File

`C:\Users\dimas\.claude\settings.json` controls which hooks fire. Removing or modifying the PreToolUse entry disables the entire gate system. This file is outside the `.command-gate/` tree and is not currently covered by the manifest. Phase 4 helios-lock should protect it.

### Mutable Runtime Envelope

Directories that must change as part of the gate lifecycle:

- `pending/` — gates awaiting execution
- `inflight/` — gates currently executing
- `evidence/` — completed gate records and integrity evidence
- `blocked/` — denied command records

### Repo-Controlled Support Assets

Files not loaded by the active hook path. Development and maintenance aids:

- `docs/` — architecture documentation
- `schemas/` — JSON Schema definitions for validation
- `tools/` — offline rebaseline, verification, cleanup tools
- `tests/` — Pester test suite

These are not part of the runtime protected envelope. Do not add them to `helios-envelope.json` unless a file is loaded by the active hook path.

## Session Baseline

`evidence/integrity/sessions/<session_id>/baseline.json` — snapshot of protected hashes at session start.

The session baseline is **evidence, not policy**:
- Created only after verifying the current envelope matches the durable manifest.
- Provides session continuity evidence ("the session started clean").
- Does not replace or override the durable manifest as root of trust.
- Drift against the baseline means something changed since the session started, even if the manifest hasn't been rebaselined.

## Dual Comparison

Every PreToolUse check compares current state against **both**:
1. **Durable manifest** — "Does the envelope match the known-good install state?"
2. **Session baseline** — "Has anything changed since this session started clean?"

If either comparison fails, Helios denies. Protected drift comparison (`Compare-HeliosProtectedEnvelope`) is separate from mutable runtime transition comparison (`Compare-HeliosRuntimeTransition`).

## Front Controller

`helios_pretooluse.ps1` is the configured PreToolUse entry point. Integrity verification happens **before** any policy code is loaded:

1. Read payload from stdin
2. Pass through non-Bash/PowerShell tools
3. Locate manifest and sidecar (fixed relative path)
4. Verify sidecar hash matches computed hash of manifest
5. Parse manifest, hash all protected files
6. Compare against manifest hashes — if drift: deny (policy code never loads)
7. Dot-source `hooks/lib/HeliosIntegrityBridge.ps1` (now verified)
8. Check/create session baseline
9. Compare against both manifest and baseline
10. Write before snapshot
11. Dot-source `tier_classifier.ps1` and `gate_check.ps1` (both now verified)
12. Re-define DenyFatal after dot-source (gate_check.ps1 override protection)
13. Run gate validation
14. Write decision evidence
15. Exit with allow or deny

The critical ordering: integrity verification at steps 4-6 happens before `tier_classifier.ps1` is loaded (step 11) and before `command-policy.json` is parsed. If those files are tampered, the tampered code never runs.

## Per-Command Evidence

```
evidence/integrity/sessions/<session_id>/
  baseline.json
  commands/
    <tool_use_id>.before.json    — pre-command protected snapshot
    <tool_use_id>.decision.json  — allow/deny/integrity_failure verdict
    <tool_use_id>.after.json     — post-command snapshot (if executed)
    <tool_use_id>.compare.json   — protected + runtime comparison (if executed)
```

Denied commands get `before.json` and `decision.json`. Allowed commands get all four files.

## Bridge API

Seven functions vendored from TCE lineage. Self-contained, no module imports. PowerShell 5.1+ compatible.

| Function | Purpose |
|---|---|
| `Get-FileSha256` | Raw-byte SHA256 of a file, lowercase hex |
| `Get-HeliosEnvelopeSnapshot` | Hash protected files, capture mutable dir state |
| `Compare-HeliosProtectedEnvelope` | Compare snapshot against manifest and/or baseline |
| `Compare-HeliosRuntimeTransition` | Lifecycle-aware comparison of mutable dirs |
| `New-HeliosSessionBaseline` | Create baseline after verifying manifest integrity |
| `Test-HeliosIntegrity` | Quick pass/fail: current files vs manifest hashes |
| `Write-HeliosIntegrityEvidence` | Write before/decision/after/compare JSON files |

### Expected Mutation Profiles

`Compare-HeliosRuntimeTransition` takes an `ExpectedMutationProfile`:

- `ALLOW_PRETOOL` — pending loses gate, inflight gains gate
- `ALLOW_POSTTOOL` — inflight loses gate, evidence gains result
- `DENY_PRETOOL` — all dirs stable, blocked gains record
- `INTEGRITY_FAILURE` — all dirs stable

## DenyFatal Invariant

`DenyFatal` must produce deny JSON on stdout and exit 0. Claude Code treats non-zero exit codes as "hook error, proceed normally" — a non-zero exit silently allows the command. The front controller re-defines DenyFatal after dot-sourcing `gate_check.ps1` to prevent override.

## Stdout Purity Rule

Hook stdout must contain only the final hook JSON response. All helper return values must be piped to `Out-Null` or captured in variables.

## Rebaseline Process

When any protected file changes:
1. A model or human proposes the change.
2. A human approves the rebaseline.
3. Run `tools/New-HeliosEnvelopeManifest.ps1 -GateRoot <path> -RebaselinedBy human`.
4. Verify: `tools/Test-HeliosEnvelopeIntegrity.ps1 -GateRoot <path>`.
5. Next gated command creates a new session baseline automatically.

## Schemas

See `schemas/` for JSON Schema definitions:

- `helios-envelope.v1.schema.json` — durable manifest
- `helios-baseline.v1.schema.json` — session baseline
- `helios-command-evidence.v1.schema.json` — per-command evidence
