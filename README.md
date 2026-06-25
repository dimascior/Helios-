# Helios

A command-gate security layer for AI agent tool execution in VS Code.

Helios intercepts every shell command an AI agent attempts to run and validates
it against a signed, single-use gate file before allowing execution. Commands
without a matching gate are blocked.

## How It Works

1. Agent issues a `Bash` or `PowerShell` tool call
2. A PreToolUse hook fires and runs `gate_check.ps1`
3. The hook searches `pending/` for a gate file whose `command_sha256` matches
4. If a valid gate exists, the command proceeds and the gate moves to `evidence/`
5. If no gate exists, the command is blocked and the required SHA256 is reported

Gates are single-use: `pending/` → `inflight/` → `evidence/`. Every executed
command leaves an auditable evidence trail.

## Risk Tiers

| Tier | Category | Examples |
|------|----------|----------|
| 0 | Routine | unlisted commands |
| 1 | Diagnostic | `ps`, `ls`, `cat`, `grep`, `Get-Process` |
| 2 | Remote/Admin | `ssh`, `sudo`, `tailscale ssh` |
| 3 | Modifying | `rm`, `git push`, `npm install`, `Set-Content` |
| 4 | Forbidden | `rm -rf /`, `mkfs`, credential dumping |

Higher tiers require additional gate fields (`stop_conditions`,
`read_write_impact`). Tier 4 commands are always blocked.

## Gate File Schema

```json
{
  "schema_version": "command-gate.v1",
  "correlation_id": "unique-id",
  "created_utc": "2026-01-01T00:00:00Z",
  "expires_utc": "2026-01-01T06:00:00Z",
  "command": "git status",
  "command_sha256": "<sha256 of command text>",
  "working_directory": "C:\\Users\\you\\project",
  "shell": "bash",
  "risk_tier": 0,
  "exit_capture": "not_applicable",
  "exit_capture_reason": "pure_output",
  "multi_command": false,
  "segments": [],
  "need": "why this command is needed",
  "expected": "what the output should look like",
  "actual_means": "how this command achieves the goal",
  "next_logic": "what happens after this command",
  "approval_boundary": "This gate makes the command eligible for permission flow only; it does not auto-approve execution."
}
```

## Chain Detection

Commands containing `;`, `&&`, `||`, or `|` outside single-quoted strings must
declare `multi_command: true` with a `segments` array. Undeclared chaining is
blocked. The detector is single-quote aware — operators inside `'...'` are
exempted.

## Structure

```
.command-gate/
  hooks/
    gate_check.ps1          PreToolUse validation hook
    tier_classifier.ps1     Risk tier and write-indicator detection
    evidence_capture.ps1    PostToolUse evidence archival
  policy/
    command-policy.json     Tier patterns and write indicators
  pending/                  Gate files awaiting execution
  inflight/                 Gates currently executing
  evidence/                 Completed gate records
  blocked/                  Rejected command records
  templates/                Gate file templates
```

## Setup

1. Place the `.command-gate/` directory in your project root
2. Configure Claude Code hooks in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "powershell -ExecutionPolicy Bypass -File .command-gate/hooks/gate_check.ps1"
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
            "command": "powershell -ExecutionPolicy Bypass -File .command-gate/hooks/evidence_capture.ps1"
          }
        ]
      }
    ]
  }
}
```

3. Create gate files in `pending/` before issuing commands

## License

MIT
