# Helios

Helios is a command-gate policy layer for Claude Code and other AI agent tool execution environments.

It turns shell execution into an explicit, auditable protocol. Before an agent can run a `Bash` or `PowerShell` command, it must create a matching single-use gate file that explains what the command is, why it is needed, what output is expected, how the result should be interpreted, and what decision the result supports.

Each command an LLM wants to execute on your system must go through a JSON gate file with a valid pre-execution command hash. The agent makes the request by filling out the gate schema parameters and running the command. Once the hash validates against the declared scope and schema, the gate returns context for that one-off command and surfaces any errors found during pre-execution validation. This verifies the command was authorized based on the scope of the command within the schema parameters, forcing the agent to explain:

- **why** the command is needed
- **what** the expected output is
- **what** the actual output means
- **why** the next command is needed

Helios does not decide whether a command is "morally okay." It decides whether this exact command, in this exact shell, from this exact working directory, with this exact hash and declared risk boundary, is eligible to reach Claude Code's normal permission flow.

Helios is not model-specific. Any model or agent can operate through it if it can write a valid `.gate.json` file and follow the gate lifecycle. The purpose is not only command safety. Helios also creates clean evidence boundaries for studying when an AI system is blocked, routed, or confused: command text, structured reasoning, command output, expected-vs-actual comparison, or next-command derivation.

## Design Principles

### The hash is not the trust boundary

The hash binds to the exact command string, not to a human-authorized allowlist. If the model is allowed to write gates, then the model can generate both sides: command and gate. The hash mainly prevents drift. It proves that the explanation, cwd, shell, tier, stop conditions, and evidence plan correspond to the exact command that is about to run. It stops "explain one command, run another."

### Base fields are cheap enough to leave on

The base fields are short: `need`, `expected`, `actual_means`, and `next_logic`. The gate program treats those as required even for Tier 0 and Tier 1, while Tier 2 adds `stop_conditions` and Tier 3 adds `read_write_impact`. The overhead is mostly a few hundred tokens plus one gate file write, not a major runtime cost compared with the value: it prevents the model from silently changing command purpose after seeing output.

Tier 0 can be terse. Tier 2/3 should be explicit. For experimental model testing, leaving it on is also cleaner because it keeps the instrumentation constant. If you toggle it, you add another variable: now you cannot tell whether a guardrail changed because of command content, explanation content, or missing explanation structure.

### The gate is binding and observable

Authorization comes from Tier 4 hard blocks, Claude Code's permission flow, and whatever human or local policy controls whether eligible commands actually execute. The gate is consumed once. Rerunning the same command needs a new gate, even if the command text is identical.

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
3. `gate_check.ps1` reads the hook payload, extracts `tool_input.command`, computes the SHA-256 of the exact command string, and classifies the command tier via `tier_classifier.ps1`.
4. Tier 4 commands are blocked unconditionally, even if a gate exists.
5. If no valid gate exists, the hook blocks the command and reports the required SHA-256.
6. If a valid gate exists, the hook validates every field — command text, hash, cwd, shell, expiry, risk tier, required fields, write-impact declarations, exit-capture rules, and chain rules — then moves it to `inflight/` and returns `{}`.
7. Claude Code proceeds through its normal permission flow.
8. After execution, `evidence_capture.ps1` looks for the matching inflight gate — preferably by `tool_use_id`, then falls back to command hash. It writes evidence sidecars (`.result.json`, `.tool_response.json`, `.stdout.txt`, `.stderr.txt`) and moves the consumed gate to `evidence/`.
9. The evidence hook injects context telling the agent to compare expected output against actual output before creating the next gate.

The agent can discover the hash by first attempting the command without a gate, reading the denied SHA-256 from the block message, writing a matching gate, then retrying the exact same command text.

Gates that cannot be matched to an inflight record are logged as orphans with a generated correlation ID.

## Lifecycle Examples by Tier

### Tier 0 — Routine

A simple directory check. Only base fields required.

**1. Agent attempts command without a gate:**

```text
> pwd; echo EXIT=$?
```

**2. PreToolUse blocks and reports the SHA-256:**

```text
GATE REQUIRED: No valid gate found in pending/ for this command.
Tier: 0. SHA256: 9f2b...c4a1. Category: routine.
```

**3. Agent writes gate file** `pending/pwd-check.gate.json`:

```json
{
  "schema_version": "command-gate.v1",
  "correlation_id": "pwd-check",
  "created_utc": "2026-06-25T12:00:00Z",
  "expires_utc": "2026-06-26T12:00:00Z",
  "command": "pwd; echo EXIT=$?",
  "command_sha256": "9f2b...c4a1",
  "working_directory": "C:\\Users\\you\\project",
  "shell": "bash",
  "risk_tier": 0,
  "exit_capture": "suffix",
  "multi_command": true,
  "segments": ["pwd", "echo EXIT=$?"],
  "need": "Verify the current working directory before writing the next gate.",
  "expected": "The output should show the project path and end with EXIT=0.",
  "actual_means": "If the path matches and EXIT=0, the cwd baseline is valid.",
  "next_logic": "Use the observed cwd as working_directory for the next gate.",
  "approval_boundary": "This gate makes the command eligible for permission flow only; it does not auto-approve execution."
}
```

**4. Agent retries. PreToolUse validates and returns `{}`** — command proceeds to Claude Code's normal permission flow.

Gate moves: `pending/pwd-check.gate.json` → `inflight/<tool_use_id>_pwd-check.gate.json`

**5. Command executes:**

```text
/c/Users/you/project
EXIT=0
```

**6. PostToolUse captures evidence.** Gate moves to `evidence/` with sidecars:

```text
evidence/
  <tool_use_id>_pwd-check.gate.json        # consumed gate
  <tool_use_id>_pwd-check.result.json       # exit code, timing, match status
  <tool_use_id>_pwd-check.stdout.txt        # raw stdout
```

**7. Evidence hook injects context** into the agent's next turn:

```text
[EVIDENCE:pwd-check] Command succeeded. Compare EXPECTED from the gate vs ACTUAL output before creating the next gate.
```

---

### Tier 1 — Diagnostic

System inspection. Same base fields as Tier 0 — no additional requirements.

**1. Agent writes gate** `pending/list-processes.gate.json`:

```json
{
  "schema_version": "command-gate.v1",
  "correlation_id": "list-processes",
  "created_utc": "2026-06-25T12:05:00Z",
  "expires_utc": "2026-06-26T12:00:00Z",
  "command": "Get-Process node -ErrorAction SilentlyContinue; Write-Host \"EXIT=$LASTEXITCODE\"",
  "command_sha256": "a3d1...e7b2",
  "working_directory": "C:\\Users\\you\\project",
  "shell": "powershell",
  "risk_tier": 1,
  "exit_capture": "suffix",
  "multi_command": true,
  "segments": [
    "Get-Process node -ErrorAction SilentlyContinue",
    "Write-Host \"EXIT=$LASTEXITCODE\""
  ],
  "need": "Check if a Node.js process is running before starting the dev server.",
  "expected": "Either a process table showing node PIDs or empty output if none are running, followed by EXIT=0.",
  "actual_means": "If node processes appear, the dev server may already be running. If empty, safe to start.",
  "next_logic": "If no node process is running, create a gate to start the dev server.",
  "approval_boundary": "This gate makes the command eligible for permission flow only; it does not auto-approve execution."
}
```

**2. PreToolUse validates and returns `{}`.**

**3. Command output:**

```text
 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
     18    45.12      52.30       2.14    7832   1 node
EXIT=0
```

**4. Evidence captured.** The hook writes `.result.json` with the parsed `EXIT=0` and the full stdout.

---

### Tier 2 — Remote / Admin

Remote access commands. Requires `stop_conditions` in addition to base fields.

**1. Agent writes gate** `pending/ssh-uptime.gate.json`:

```json
{
  "schema_version": "command-gate.v1",
  "correlation_id": "ssh-uptime",
  "created_utc": "2026-06-25T12:10:00Z",
  "expires_utc": "2026-06-26T12:00:00Z",
  "command": "ssh deploy@staging.example.com 'uptime'; echo EXIT=$?",
  "command_sha256": "c8f4...19d3",
  "working_directory": "C:\\Users\\you\\project",
  "shell": "bash",
  "risk_tier": 2,
  "exit_capture": "suffix",
  "multi_command": true,
  "segments": [
    "ssh deploy@staging.example.com 'uptime'",
    "echo EXIT=$?"
  ],
  "need": "Verify staging server is reachable and check load before deploying.",
  "expected": "Uptime output showing the server is up with reasonable load averages, followed by EXIT=0.",
  "actual_means": "If uptime returns and load is under 4.0, the server is healthy enough to deploy to.",
  "next_logic": "If healthy, create a Tier 3 gate for the deploy command. If unreachable, stop and report.",
  "stop_conditions": [
    "Stop if SSH authentication fails or connection is refused.",
    "Stop if load average exceeds 4.0 — the server is under too much load to deploy."
  ],
  "approval_boundary": "This gate makes the command eligible for permission flow only; it does not auto-approve execution."
}
```

**2. PreToolUse validates.** If `stop_conditions` were missing:

```text
GATE REJECTED: closest gate ssh-uptime.gate.json matched sha256 but failed validation:
- missing tier-required fields: stop_conditions
```

With `stop_conditions` present, returns `{}`.

**3. Command output:**

```text
 12:10:05 up 42 days,  3:15,  2 users,  load average: 0.45, 0.62, 0.58
EXIT=0
```

**4. Evidence hook injects context:**

```text
[EVIDENCE:ssh-uptime] Command succeeded. Compare EXPECTED from the gate vs ACTUAL output before creating the next gate.
```

The agent reads the load averages, compares against the stop condition threshold, and decides whether to proceed.

---

### Tier 3 — Modifying

State-changing commands. Requires `stop_conditions` and `read_write_impact` in addition to base fields.

**1. Agent writes gate** `pending/push-main.gate.json`:

```json
{
  "schema_version": "command-gate.v1",
  "correlation_id": "push-main",
  "created_utc": "2026-06-25T12:15:00Z",
  "expires_utc": "2026-06-26T12:00:00Z",
  "command": "git push origin main; echo EXIT=$?",
  "command_sha256": "d2a7...f103",
  "working_directory": "C:\\Users\\you\\project",
  "shell": "bash",
  "risk_tier": 3,
  "exit_capture": "suffix",
  "multi_command": true,
  "segments": [
    "git push origin main",
    "echo EXIT=$?"
  ],
  "need": "Push the committed README update to the remote repository.",
  "expected": "Push output showing objects written and refs updated on origin/main, followed by EXIT=0.",
  "actual_means": "If push succeeds, the changes are live on the remote. If rejected, a pull or rebase is needed first.",
  "next_logic": "If push succeeds, report completion. If rejected as non-fast-forward, create a gate for git pull --rebase.",
  "stop_conditions": [
    "Stop if authentication fails.",
    "Stop if push is rejected as non-fast-forward — do not force push without explicit authorization."
  ],
  "read_write_impact": {
    "reads": ["local main branch history"],
    "writes": ["origin/main ref on remote repository"]
  },
  "approval_boundary": "This gate makes the command eligible for permission flow only; it does not auto-approve execution."
}
```

**2. PreToolUse validates.** If `read_write_impact` were missing or had `writes: ["none"]`:

```text
GATE REJECTED: closest gate push-main.gate.json matched sha256 but failed validation:
- write indicator detected but read_write_impact.writes is missing
```

With all fields present, returns `{}`.

**3. Command output:**

```text
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Writing objects: 100% (3/3), 722 bytes | 722.00 KiB/s, done.
To https://github.com/you/project.git
   a31f125..5a43d10  main -> main
EXIT=0
```

**4. Evidence sidecars:**

```text
evidence/
  <tool_use_id>_push-main.gate.json
  <tool_use_id>_push-main.result.json
  <tool_use_id>_push-main.tool_response.json   # full Claude Code tool response (capped 1MB)
  <tool_use_id>_push-main.stdout.txt
  <tool_use_id>_push-main.stderr.txt            # git progress output
```

---

### Tier 4 — Forbidden

Always blocked. No gate can authorize a Tier 4 command.

**1. Agent attempts command:**

```text
> rm -rf /
```

**2. PreToolUse blocks unconditionally:**

```text
TIER 4 BLOCKED: Command matches forbidden pattern. Category: destructive disk command.
No gate can authorize this command.
```

The block fires before gate matching. Even if a gate exists in `pending/` with a correct SHA-256, Tier 4 commands never reach the validation stage. The attempt is written to `blocked/` for audit.

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

### Directory Integrity

On every invocation, `gate_check.ps1` checks that the gate root and all required subdirectories exist and are not reparse points (junctions or symlinks). This prevents an attacker from redirecting the gate store to a location they control.

### Tier Classification

The tier classifier loads patterns from `command-policy.json` at runtime and exports three functions: `Get-CommandTier`, `Test-ChainViolation`, and `Test-WriteIndicator`. Risk logic is not spread across memory or hooks; the policy file is the single operational source for tier patterns and write indicators.

If an `operating-catalog.json` exists in `templates/`, the classifier checks it after Tier 4 but before Tier 3, allowing project-specific pattern overrides with template suggestions.

## Risk Tiers

| Tier | Category | Examples | Additional requirements |
|------|----------|----------|-------------------------|
| 0 | Routine | unlisted commands | base gate fields |
| 1 | Diagnostic | `ps`, `ls`, `cat`, `grep`, `Get-Process` | base gate fields |
| 2 | Remote/Admin | `ssh`, `sudo`, `tailscale ssh`, selected `rv` actions | `stop_conditions` |
| 3 | Modifying | `rm`, `git push`, `npm install`, `Set-Content`, `mkdir` | `stop_conditions`, `read_write_impact` |
| 4 | Forbidden | destructive disk commands, credential dumping, unsafe pipe-to-shell patterns | always blocked |

Tier 4 commands are blocked even if a gate exists.

### Write Indicators

If a command matches any write indicator pattern (e.g., `git commit`, `rm`, `> `, `Set-Content`), the gate must declare `read_write_impact` with a non-empty, non-`["none"]` `writes` array — regardless of tier. This catches cases where a Tier 0 command still performs writes.

## Gate Schema

The gate file must be JSON and must be placed in `.command-gate/pending/` before the command is retried.

A minimal Tier 0 gate looks like this:

A valid gate must bind the exact command and include these required base fields:

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

Exit capture is one of the most important design pieces. Claude Code's `PostToolUseFailure` payload does not include `tool_response`, so when a command exits nonzero normally, Helios may lose stdout, stderr, and exit code. Helios therefore requires commands to expose their own exit code as `EXIT=<number>` unless the gate explicitly marks exit capture as not applicable.

| Mode | When to Use | Behavior |
|------|------------|----------|
| `suffix` | Simple commands | Command ends with an approved exit-capture suffix (e.g., `; echo EXIT=$?`). Tool may exit nonzero and trigger `PostToolUseFailure`, losing `tool_response`. |
| `wrapper_required` | Commands that may fail | Wrapper captures the real exit code, prints `EXIT=<code>`, and exits 0. Tool always triggers `PostToolUse` so the evidence hook receives full output. Wrapper commands are exempt from chain detection. |
| `not_applicable` | No meaningful exit code | Requires an approved reason: `pure_output`, `no_exit_code_semantic`, `interactive_tool`, or `background_process`. |

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

The full command hash protects the complete wrapper. The wrapped command hash documents the command being measured inside the wrapper. The full command must also pass structural validation: it must contain the shell-specific marker (`echo "EXIT=` for bash, `Write-Host "EXIT=` for PowerShell) and end with `exit 0`.

### `not_applicable`

Use this only when no meaningful exit code exists for the command.

```json
"exit_capture": "not_applicable",
"exit_capture_reason": "pure_output"
```

The reason must be approved by `command-policy.json`.

## Chain Detection

Commands containing `;`, `&&`, `||`, or `|` outside single-quoted strings are treated as chained commands. Chained commands must declare:

```json
"multi_command": true,
"segments": [
  "first command",
  "second command"
]
```

Undeclared chaining is blocked.

The detector is single-quote aware: operators inside `'...'` are exempted. Double-quote false positives deliberately overblock (safe direction). This is a strict policy — no chain exemptions exist except for wrapper-mode commands, where the wrapper structure is the approved pattern.

Exit-capture suffixes and wrapper scaffolding are handled by policy. If your command includes a suffix such as `; echo EXIT=$?`, either the suffix must be recognized as chain-exempt by `tier_classifier.ps1`, or the gate must declare the command as `multi_command: true` with `segments`.

## Diagnostics

The PreToolUse hook does not return a binary pass/fail. When it blocks a command, it returns structured context explaining exactly why the gate was rejected — which field was wrong, what the expected value was, what the actual value was, and what is still missing. The agent receives this context as part of the hook response and can use it to correct the gate and retry without guessing.

This is a deliberate design choice. A simple exit code 0 or 1 would force the agent into blind retry loops or require a human to diagnose every rejection. Instead, the hook acts as a validation report: it tells the agent what to fix, not just that something failed.

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

Place `.command-gate/` in the project root. The hook scripts derive `$GateRoot` automatically from their own location (`Split-Path $PSScriptRoot -Parent`), so no path editing is needed — just update the hook command paths in `settings.json` to point to your copy.

Configure Claude Code hooks in `~/.claude/settings.json`, replacing `<project>` with the absolute path to your project root:

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
            "command": "& '<project>\\.command-gate\\hooks\\gate_check.ps1'",
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
            "command": "& '<project>\\.command-gate\\hooks\\evidence_capture.ps1'",
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
            "command": "& '<project>\\.command-gate\\hooks\\evidence_capture.ps1'",
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

Create gate files in `pending/` before issuing commands. The agent discovers the required SHA-256 by attempting the command, reading the hash from the block message, and writing a gate that matches.

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
