# Helios

Helios is a command-gate policy layer for Claude Code and other AI agent tool execution environments.

It turns shell execution into an explicit, auditable protocol. Before an agent can run a `Bash` or `PowerShell` command, it must create a matching single-use gate file that explains what the command is, why it is needed, what output is expected, how the result should be interpreted, and what decision the result supports.

Helios is not model-specific. Any model or agent can operate through it if it can write a valid `.gate.json` file and follow the gate lifecycle. The purpose is not only command safety. Helios also creates clean evidence boundaries for studying when an AI system is blocked, routed, or confused: command text, structured reasoning, command output, expected-vs-actual comparison, or next-command derivation.

## Core Idea

A command is not allowed merely because the model wants to run it.

A command becomes eligible for normal Claude Code permission flow only when a gate exists in `pending/` and matches all of these conditions:

- exact command text
- SHA-256 of the exact command text
- current working directory
- shell name, `bash` or `powershell`
- unexpired timestamp
- sufficient risk tier
- required schema fields
- exit-capture policy
- write-impact declaration when the command can modify state
- multi-command declaration when chaining is used

A valid gate does not auto-approve execution. It only allows the command to proceed to the normal permission layer.

## Lifecycle

```text
pending/   -> PreToolUse validates -> inflight/ -> PostToolUse captures -> evidence/
blocked/   <- denied attempts
```

The gate lifecycle is single-use.

1. The agent attempts a `Bash` or `PowerShell` command.
2. Claude Code fires the `PreToolUse` hook.
3. `gate_check.ps1` hashes the exact command and searches `pending/`.
4. If no valid gate exists, the hook blocks the command and reports the required SHA-256.
5. If a valid gate exists, the hook moves it to `inflight/` and returns `{}`.
6. Claude Code proceeds through its normal permission flow.
7. After execution, `evidence_capture.ps1` moves the gate to `evidence/` and writes result sidecars.
8. The evidence hook injects context telling the agent to compare expected output against actual output before creating the next gate.

## Directory Structure

```text
.command-gate/
  hooks/
    gate_check.ps1          PreToolUse validation hook
    tier_classifier.ps1     Risk tier, chain, and write-indicator detection
    evidence_capture.ps1    PostToolUse / PostToolUseFailure evidence capture
    debug_hook.ps1          Optional payload discovery hook
  policy/
    command-policy.json     Tier patterns, exit-capture policy, write indicators
  pending/                  Gates waiting to be consumed
  inflight/                 Gates currently executing
  evidence/                 Completed gate records and sidecars
  blocked/                  Rejected command records
  templates/                Gate templates and catalog entries
```

## Risk Tiers

| Tier | Category | Examples | Additional requirements |
|------|----------|----------|-------------------------|
| 0 | Routine | unlisted commands | base gate fields |
| 1 | Diagnostic | `ps`, `ls`, `cat`, `grep`, `Get-Process` | base gate fields |
| 2 | Remote/Admin | `ssh`, `sudo`, `tailscale ssh`, selected `rv` actions | `stop_conditions` |
| 3 | Modifying | `rm`, `git push`, `npm install`, `Set-Content`, `mkdir` | `stop_conditions`, `read_write_impact` |
| 4 | Forbidden | destructive disk commands, credential dumping, unsafe pipe-to-shell patterns | always blocked |

Tier 4 commands are blocked even if a gate exists.

## Gate Schema

The gate file must be JSON and must be placed in `.command-gate/pending/` before the command is retried.

A minimal Tier 0 gate looks like this:

```json
{
  "schema_version": "command-gate.v1",
  "correlation_id": "unique-gate-id",
  "created_utc": "2026-06-25T12:00:00Z",
  "expires_utc": "2026-07-02T12:00:00Z",
  "command": "pwd; echo EXIT=$?",
  "command_sha256": "<sha256 of exact command text>",
  "working_directory": "C:\\Users\\dimas\\Desktop\\Engineering",
  "shell": "bash",
  "risk_tier": 0,
  "exit_capture": "suffix",
  "multi_command": true,
  "segments": [
    "pwd",
    "echo EXIT=$?"
  ],
  "need": "Verify the current working directory before writing the next gate.",
  "expected": "The output should show the active project path and end with EXIT=0.",
  "actual_means": "If the path matches the gate working_directory and EXIT=0 appears, the cwd baseline is valid.",
  "next_logic": "Use the observed cwd as working_directory for the next gate.",
  "approval_boundary": "This gate makes the command eligible for permission flow only; it does not auto-approve execution."
}
```

Important field names:

- Use `risk_tier`, not `tier`.
- Use `working_directory` that matches the actual Claude Code payload cwd.
- Use `shell` as lowercase `bash` or `powershell`.
- Use `command_sha256` for the exact command string, byte-for-byte.
- Gates are consumed once. Re-running the same command needs a new gate file and a new `correlation_id`.

## Conditional Fields

Tier 2 and Tier 3 gates require `stop_conditions`.

```json
"stop_conditions": [
  "Stop if the command fails authentication.",
  "Stop if the output does not match the expected target host."
]
```

Commands with write indicators require `read_write_impact.writes`. This is enforced independently of the detected tier.

```json
"read_write_impact": {
  "reads": [".command-gate/pending"],
  "writes": [".command-gate/evidence/rejected-tests"]
}
```

`writes` cannot be missing, empty, or `["none"]` when a write indicator is detected.

## Exit Capture

Claude Code hook payloads may include `stdout`, `stderr`, and `interrupted`, but they do not reliably include a native process exit code. Helios therefore requires commands to expose their own exit code as `EXIT=<number>` unless the gate explicitly marks exit capture as not applicable.

Supported modes:

### `suffix`

Use this when the command is expected to succeed normally and the shell can append a simple marker.

Bash:

```bash
pwd; echo EXIT=$?
```

PowerShell native executable:

```powershell
git status; Write-Host "EXIT=$LASTEXITCODE"
```

### `wrapper_required`

Use this when the semantic command may return a nonzero exit code and that nonzero result is meaningful diagnostic evidence. The wrapper captures the real exit code, prints `EXIT=<number>`, and exits `0` so Claude Code fires `PostToolUse` and provides `tool_response` to the evidence hook.

PowerShell example:

```powershell
$actualExit = 0
try {
    cmd /c "exit 1"
    $actualExit = $LASTEXITCODE
} catch {
    Write-Error $_
    $actualExit = 1
}
Write-Host "EXIT=$actualExit"
exit 0
```

Wrapper gates must declare the semantic command identity:

```json
"exit_capture": "wrapper_required",
"wrapped_command": "cmd /c \"exit 1\"",
"wrapped_command_sha256": "<sha256 of wrapped_command>",
"wrapper_reason": "The semantic command may return nonzero and must be captured as evidence rather than becoming a tool-level failure."
```

The full command hash protects the complete wrapper. The wrapped command hash documents the command being measured inside the wrapper.

### `not_applicable`

Use this only when no meaningful exit code exists for the command.

```json
"exit_capture": "not_applicable",
"exit_capture_reason": "pure_output"
```

The reason must be approved by `command-policy.json`.

## Chain Detection

Commands containing `;`, `&&`, `||`, or `|` outside quoted strings are treated as chained commands. Chained commands must declare:

```json
"multi_command": true,
"segments": [
  "first command",
  "second command"
]
```

Undeclared chaining is blocked.

Exit-capture suffixes and wrapper scaffolding are handled by policy. If your command includes a suffix such as `; echo EXIT=$?`, either the suffix must be recognized as chain-exempt by `tier_classifier.ps1`, or the gate must declare the command as `multi_command: true` with `segments`.

## Diagnostics

Helios should not make the agent guess why a gate failed.

If no plausible gate exists, the hook reports:

```text
GATE REQUIRED: No valid gate found in pending/ for this command. Tier: 0. SHA256: <hash>. Category: routine.
```

If a pending gate has the same SHA-256 or command text but fails validation, the hook should report the closest rejection reason:

```text
GATE REJECTED: closest gate pwd-probe.gate.json matched sha256 but failed validation:
- working_directory mismatch
  gate:   C:\Users\dimas\Desktop\Engineering
  actual: C:\Users\dimas\Desktop\Engineering\src
```

Common diagnostics include:

- `field name error: found "tier"; expected "risk_tier"`
- `missing base fields: schema_version, correlation_id, created_utc, ...`
- `missing tier-required fields: need, expected, actual_means, next_logic`
- `working_directory mismatch`
- `expired gate`
- `risk_tier too low`
- `write indicator detected but read_write_impact.writes is missing`
- `EXIT CAPTURE REQUIRED`
- `UNDECLARED CHAINING`

Blocked attempts are written to `.command-gate/blocked/` for audit and recovery.

## Compaction Recovery Rules

After context compaction, do not rely on memory alone. Use this checklist before writing gates:

1. Gate and run `pwd` first to establish the current working directory.
2. Remember that `cd` changes cwd persistently for the session. Every later gate must use the new cwd.
3. Use `risk_tier`, not `tier`.
4. Include all base fields from the schema template.
5. Include `stop_conditions` for Tier 2 and Tier 3.
6. Include `read_write_impact.writes` for write commands.
7. Include an exit-capture mode.
8. Use far-future expiry for active work sessions.
9. Gates are single-use. Re-running a command requires a new gate.
10. If a gate fails, read the rejection reason from the hook or the matching file in `blocked/`.

## Fable / Guardrail Localization Use

Helios can be used as an instrumentation layer for Fable-style guardrail research.

The gate separates the execution loop into observable phases:

```text
command text -> gate fields -> command execution -> raw output -> expected-vs-actual comparison -> next-step derivation
```

That separation helps identify whether a model is being routed or blocked because of:

- the command string itself
- structured operational reasoning
- remote/admin context
- raw output text
- expected-vs-actual comparison
- root-cause analysis
- next-command derivation
- the full agentic control loop

For guardrail localization, do not give the tested model the full operator playbook at first. Feed one controlled lane at a time so the trigger can be isolated.

## Setup

Place `.command-gate/` in the project root or update `$GateRoot` inside the hook scripts to the intended absolute directory.

Configure Claude Code hooks in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "shell": "powershell",
            "command": "& 'C:\\Users\\dimas\\Desktop\\Engineering\\.command-gate\\hooks\\gate_check.ps1'",
            "timeout": 15
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "shell": "powershell",
            "command": "& 'C:\\Users\\dimas\\Desktop\\Engineering\\.command-gate\\hooks\\evidence_capture.ps1'",
            "timeout": 15
          }
        ]
      }
    ],
    "PostToolUseFailure": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "shell": "powershell",
            "command": "& 'C:\\Users\\dimas\\Desktop\\Engineering\\.command-gate\\hooks\\evidence_capture.ps1'",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

Use `debug_hook.ps1` first when installing Helios in a new Claude Code environment. Confirm the actual payload contains:

- `tool_name`
- `tool_input.command`
- `cwd`
- `tool_use_id`
- `tool_response.stdout` and `tool_response.stderr` for `PostToolUse`

## Validation Checklist

Before relying on Helios for real work, verify:

- no-gate command is blocked and reports SHA-256
- valid gate moves `pending/` to `inflight/` to `evidence/`
- expired gate is rejected with an expiry diagnostic
- cwd mismatch is reported clearly
- `tier` vs `risk_tier` mistake is reported clearly
- write-indicator command with `writes: ["none"]` is rejected
- undeclared chain is rejected
- Tier 4 command is blocked even with a gate
- wrapper-required command captures semantic `EXIT=<number>` through `PostToolUse`
- `PostToolUseFailure` records failure even when `tool_response` is missing

## License

MIT
