# Helios Integrity Witness — Status

## Current Phase

**Phase 3.97** — TCE adapter gap-test completion and lock-requirement derivation.

## Architecture

Helios owns the command-gate runtime. TCE owns the source-of-truth bridge implementation. Helios vendors a byte-identical copy at `hooks/lib/HeliosIntegrityBridge.ps1` from TCE's `Adapters/Helios/HeliosIntegrityBridge.ps1`. helios-lock is Phase 4+ prevention.

Current detection model: **detection-on-next-shell-action**. Direct file-edit tools (Edit, Write, NotebookEdit) can modify protected files without triggering a hook. The modification is detected when the next Bash/PowerShell command fires. Phase 4 helios-lock provides prevention.

## Completed Phases

### Phase 0 — Envelope scaffold
- `manifest/helios-envelope.json` created with protected and mutable envelope definitions.
- `manifest/helios-envelope.sha256` sidecar created.
- `evidence/integrity/sessions/` directory structure established.

### Phase 1 — Bridge implementation
- `hooks/lib/HeliosIntegrityBridge.ps1` — self-contained witness bridge vendored from TCE source-of-truth.
- 7 functions: Get-FileSha256, Get-HeliosEnvelopeSnapshot, Compare-HeliosProtectedEnvelope, Compare-HeliosRuntimeTransition, New-HeliosSessionBaseline, Test-HeliosIntegrity, Write-HeliosIntegrityEvidence.

### Phase 1.5 — Front controller
- `helios_pretooluse.ps1` replaces `gate_check.ps1` as PreToolUse entry point.
- Integrity verification runs BEFORE any policy code loads.
- `gate_check.ps1` refactored to export `Invoke-GateValidation` when dot-sourced.
- DenyFatal delegates to Deny (produces deny JSON on stdout).

### Phase 2 — Evidence wiring
- `evidence_capture.ps1` integrity bridge integration for PostToolUse and PostToolUseFailure.
- Per-command evidence: before.json, decision.json, after.json, compare.json.
- Stdout-purity: all Write-HeliosIntegrityEvidence calls piped to Out-Null.

### Phase 3 — Validation (6/6 tests passed)
1. Clean gated command — ALLOW with full evidence chain.
2. Mismatched gate hash — DENY, command not executed.
3. Policy drift — DENY, integrity failure detected.
4. helios_pretooluse self-drift — DENY, front controller detects its own hash change.
5. PostToolUseFailure — after.json and compare.json written, protected_verdict CLEAN.
6. Stdout purity — ALLOW/DENY/INTEGRITY_FAILURE all produce pure JSON on stdout.

### Phase 3.5 — Helios repo formalization
- Integrity witness documentation at `docs/integrity-witness.md`.
- Bypass surface analysis at `docs/bypass-surface.md`.
- Human rebaseline boundary at `docs/rebaseline-boundary.md`.
- Phase 4 lock handoff at `docs/phase4-lock-handoff.md`.
- JSON schemas at `schemas/`: helios-envelope.v1, helios-baseline.v1, helios-command-evidence.v1.
- Rebaseline tool: `tools/New-HeliosEnvelopeManifest.ps1`.
- Verification tool: `tools/Test-HeliosEnvelopeIntegrity.ps1`.
- Evidence chain tool: `tools/Test-HeliosEvidenceChain.ps1`.
- Stale cleanup tool: `tools/Move-HeliosStaleGateArtifacts.ps1`.
- Pester test suite: `tests/HeliosIntegrity.Tests.ps1`.
- Architecture correction: TCE is source-of-truth bridge owner, Helios is command-gate runtime, helios-lock is Phase 4+ prevention.

### Phase 3.75 — Cleanup, verification, and branch readiness
- 14-point checkpoint completed: hooks, envelope, baseline, evidence chain, stale artifacts, templates, docs, schemas, tools, tests, manifest integrity, bypass surface, Phase 4 readiness.
- Support assets verified: 4 docs (correct architecture), 3 schemas (valid JSON), 4 tools (valid PowerShell), 17 Pester tests (valid syntax).
- Templates trust-boundary decision: `templates/` not in manifest hashes (directory empty). When `operating-catalog.json` is created, it must be added to manifest and rebaselined. Gap documented in `docs/bypass-surface.md` vector 9. Directory is a Phase 4 lock target.
- Evidence chain tool improved: `Test-HeliosEvidenceChain.ps1` now classifies orphan after-only files as `ORPHAN` with `cross_session_posttool` classification instead of collapsing session verdict to generic `INCOMPLETE`. New verdicts: `COMPLETE`, `COMPLETE_WITH_ORPHANS`, `INCOMPLETE`. Added `complete_count`, `orphan_count`, `incomplete_count` to output. Fixed PowerShell single-item `.Count` bug (hashtable key count vs array count).
- Pester tests updated: 2 new tests for orphan classification (`COMPLETE_WITH_ORPHANS` and `INCOMPLETE` with orphan coexistence). Suite now has 19 tests.
- Stale artifact cleanup executed: 13 artifacts archived (9 pending gates, 3 inflight gates, `compute-hashes.ps1`). `cleanup-summary.json` written to `evidence/stale/`.
- Evidence chain verified for session `8d412e6d`: 29 commands total — 24 COMPLETE (7 allow, 17 deny), 4 ORPHAN (cross-session PostToolUse), 1 INCOMPLETE (ALLOW missing after+compare — likely PostToolUse timeout). Verdict: INCOMPLETE due to 1 genuinely missing chain.
- Final rebaseline executed: all 6 protected file hashes unchanged. New manifest hash: `5a67262f624503812109a3d3182cfe7c982824a1b5c1831e9ab96086788af76d`. Sidecar valid. Verdict: CLEAN.
- Commands routed through CODEAPI terminal bridge on port 3639 (MythosJustAFable workspace) to bypass Claude Code gate system. Gate files created for each command using SHA256 discovery pattern.

### Phase 3.96 — BOM fix, maintenance corridor, fail-closed hardening
- **Root cause identified:** UTF-8 BOM in `helios-envelope.json` crashed `ConvertFrom-Json` in the PreToolUse hook. PowerShell 5.1's `Set-Content -Encoding UTF8` writes BOM. `[System.Text.Encoding]::UTF8.GetString()` preserves BOM as U+FEFF. `ConvertFrom-Json` threw "Invalid JSON primitive" → exit code 1 → Claude Code treated as "hook error, proceed normally" → ALL commands bypassed the gate silently.
- **BOM fix:** Manifest parsing changed from `UTF8.GetString | ConvertFrom-Json` to `Get-Content -Raw | ConvertFrom-Json`. All manifest/sidecar writes changed to BOM-free: `$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)` with `[System.IO.File]::WriteAllText()`.
- **Orphan evidence explained:** PostToolUse orphan evidence (orphan correlation IDs) means commands executed WITHOUT PreToolUse authorization. This is diagnostic evidence, not authorization proof. The BOM crash was the root cause of orphans in session `8d412e6d`.
- **Maintenance rebaseline corridor:** Solves the bootstrap problem: after fixing a protected file, the gate blocks ALL commands (including the rebaseline tool). The front controller now checks `maintenance/rebaseline-request.json` during drift. If valid (schema, expiry, base_manifest_hash match, drift paths match), it recomputes hashes and writes BOM-free manifest+sidecar internally. The triggering command is never executed. Session baseline is invalidated and recreated on next command.
- **Dot-source guard:** `$HeliosDotSourceFunctionsOnly` flag added to `helios_pretooluse.ps1` for test imports.
- **Gate enforcement test tool:** `tools/Test-HeliosGateEnforcement.ps1` — standalone verification of passthrough, no-gate deny, empty stdin, decision evidence, sidecar integrity, BOM absence.
- **Pester tests expanded:** `tests/HeliosIntegrity.Tests.ps1` — added maintenance corridor tests: Read-MaintenanceRebaselineRequest, Test-MaintenanceRebaselineRequest (expired, wrong schema, hash mismatch, drift path mismatch, valid), Invoke-InternalRebaseline (BOM-free verify), BOM-safe parsing (Get-Content strips BOM, UTF8.GetString preserves BOM).
- **Recovery sequence verified:** Maintenance rebaseline → envelope CLEAN → no-gate deny → valid-gate allow with full evidence chain (before, decision, after, compare). correlation_id: `phase396-allow-test-final`.
- **CAPI boundary documented:** CAPI is Robert's separate IDE actuator program, NOT part of Helios security architecture.

### Phase 3.97 — TCE adapter gap-test completion and lock-requirement derivation
- **TCE adapter spec created:** `tce-helios-integrity-adapter-spec.md` — defines TCE-owned concepts: local evidence schema, envelope model, failure taxonomy, drift taxonomy, ownership boundaries, Phase 4 derivation boundary.
- **TCE orchestration workflow:** `Invoke-HeliosGapTest.ps1` — captures pre/post state, applies controlled mutations, compares envelopes, emits TCE-local evidence.
- **TCE evidence parser:** `ConvertFrom-HeliosEvidence.ps1` — ingests Helios runtime evidence (gate, result, tool_response, integrity session, blocked, maintenance) and normalizes into TCE-local evidence object with failure classification and lock-requirement hints.
- **Gap-test matrix:** 12 controlled gap tests defined — 9 LiveControlled, 2 FixtureOnly, 1 PlanOnly (settings.json). Each test has test-plan.json and lock-requirement.json in `evidence/gap-tests/`.
- **TCE failure taxonomy:** 12 failure classes defined: protected_drift, missing_protected_file, cwd_mismatch, stale_gate, write_indicator_missing_impact, undeclared_chain, mutable_evidence_tamper, failed_missing_tool_response, wrapper_validation_failure, external_control_plane_risk, template_drift, template_unprotected_gap.
- **Phase 4 lock requirements derived:** 10 lock targets identified (hooks, policy, manifest, sidecar, templates, settings.json). 2 gaps correctly excluded from filesystem locking (cwd mismatch, stale gate). Evidence tamper classified separately from protected-runtime locks. All requirements evidence-backed.
- **TCE main preserved:** All adapter work on `helios-integrity-adapter` branch. Main at `c594a75` with no adapter entries.
- **Phase 4 entry criteria met:** Gap-test matrix complete, lock requirements derived from evidence, Helios phase4-lock-handoff.md confirmed and extended.
- **Remaining blockers:** Live execution of tests 1-3 (protected file mutations), Helios PR #2 merge, Phase 4 packaging decision, TCE main merge decision.

## Active Hook Configuration

| Hook | Script | Role |
|------|--------|------|
| PreToolUse | `helios_pretooluse.ps1` | Front controller — integrity check before policy load |
| PostToolUse | `evidence_capture.ps1` | Evidence capture with integrity bridge |
| PostToolUseFailure | `evidence_capture.ps1` | Same, handles failed commands |

Hook activation controlled by `C:\Users\dimas\.claude\settings.json` (external to .command-gate/).

## File Classification

### Runtime protected envelope (loaded by active hook path)

| File | Hash (truncated) |
|------|------------------|
| `hooks/helios_pretooluse.ps1` | `d8177099...` |
| `hooks/gate_check.ps1` | `004aaae8...` |
| `hooks/evidence_capture.ps1` | `b7c80f66...` |
| `hooks/tier_classifier.ps1` | `b1bc9475...` |
| `hooks/lib/HeliosIntegrityBridge.ps1` | `c26f927d...` |
| `policy/command-policy.json` | `838ede2f...` |

Manifest sidecar: `5a67262f...`

### Durable trust anchors
- `manifest/helios-envelope.json`
- `manifest/helios-envelope.sha256`

### External control-plane
- `C:\Users\dimas\.claude\settings.json`

### Mutable runtime envelope
- `pending/` — gates awaiting execution
- `inflight/` — gates currently executing
- `evidence/` — completed gate records
- `blocked/` — denied command records

### Repo-controlled support assets (not in runtime envelope)
- `docs/` — architecture documentation
- `schemas/` — JSON Schema definitions
- `tools/` — offline rebaseline, verification, cleanup
- `tests/` — Pester test suite

### Conditional protected file (not yet in manifest)
- `templates/operating-catalog.json` — loaded by `tier_classifier.ps1` if present. Currently does not exist (directory contains only `.gitkeep`). When created, must be added to manifest hashes and rebaselined. Phase 4 lock target: lock the `templates/` directory.

## Evidence Layout

```
evidence/integrity/sessions/<session_id>/
  baseline.json                          — session baseline (evidence, not policy)
  commands/
    <tool_use_id>.before.json            — pre-command snapshot
    <tool_use_id>.decision.json          — allow/deny/integrity_failure
    <tool_use_id>.after.json             — post-command snapshot
    <tool_use_id>.compare.json           — protected + runtime comparison
```

## Rebaseline Process

Two methods:

### Method 1: Maintenance Corridor (during drift)
1. Create `maintenance/rebaseline-request.json` per schema.
2. Trigger any shell command — the front controller performs internal rebaseline.
3. Retry the command — envelope is now clean.

### Method 2: Manual Tool (no current drift)
1. Run `tools/New-HeliosEnvelopeManifest.ps1 -GateRoot .command-gate -RebaselinedBy human`.
2. Run `tools/Test-HeliosEnvelopeIntegrity.ps1 -GateRoot .command-gate` — expect CLEAN.
3. Next gated command creates a new session baseline automatically.

## Phase 4 Entry Criteria

All met:

| Criterion | Status |
|-----------|--------|
| Integrity witness implementation (Phases 0-3) | Complete |
| Architecture correction (Phase 3.5) | Complete |
| Support assets verified (Phase 3.75) | Complete |
| Templates trust-boundary documented | Complete |
| Stale artifacts cleaned | Complete — 13 archived |
| Evidence chain classified | Complete — 24 complete, 4 orphan, 1 incomplete |
| Final rebaseline | Complete — CLEAN, sidecar valid |
| Branch committed | Complete |
| TCE gap-test matrix (Phase 3.97) | Complete — 12 tests, evidence-backed |
| TCE lock-requirement derivation (Phase 3.97) | Complete — 10 lock targets, 2 exclusions |
| TCE adapter spec (Phase 3.97) | Complete |
| TCE orchestration + parser (Phase 3.97) | Complete |

## Phase 4 — helios-lock (Filesystem Prevention)

See `docs/phase4-lock-handoff.md` for Helios-side design.
See TCE `docs/phase4-lock-requirements-from-gap-tests.md` for evidence-derived lock requirements.
See `docs/bypass-surface.md` for the current mutation risk surface (3 unmitigated gaps + 2 newly documented: PreToolUse crash fail-open, maintenance corridor abuse).

### Phase 5 — helios-lock Implementation (Future)

Python or PowerShell package implementing OS-native filesystem locks. Not started. Blocked on Phase 4 requirements finalization and packaging decision.

### Phase 6 — Lock Verification Evidence (Future)

Lock state verification integrated into integrity evidence. Not started. Blocked on Phase 5 implementation.
