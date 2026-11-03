# helios_pretooluse.ps1 — Helios PreToolUse front controller
# Integrity verification before any policy code loads. Virtual introspection
# operations (helios gate schema/scaffold/version/capabilities) are answered by
# this controller itself over the HELIOS/1 wire grammar — nothing executes, no
# gate is consumed. On protected-runtime drift Helios FAILS CLOSED and directs
# recovery to Akashic (helios-integrity-adapter); Helios never rewrites its own
# manifest or accepts drifted protected files as a new baseline.
# When dot-sourced with $HeliosDotSourceFunctionsOnly = $true, exports helper
# functions without executing the main flow.

$ErrorActionPreference = 'Stop'

$GateRoot = Split-Path $PSScriptRoot -Parent

# Bounded stage tracing for the PreToolUse decision gap. This writes one small
# JSONL record per stage outside both repositories and never scans evidence.
$script:HeliosTraceRunId = [guid]::NewGuid().ToString('N')
$script:HeliosTraceClock = [System.Diagnostics.Stopwatch]::StartNew()
$script:HeliosTracePath = Join-Path $env:LOCALAPPDATA 'HeliosPreToolUseDiagnostics\stage-trace.jsonl'
$script:HeliosTraceToolUseId = ''
$script:HeliosTraceCommandSha256 = ''

function Write-HeliosPreToolTrace {
    param(
        [Parameter(Mandatory)][string]$Stage,
        [string]$ErrorType = '',
        [string]$ErrorMessage = ''
    )
    try {
        $message = [string]$ErrorMessage
        if ($message.Length -gt 512) { $message = $message.Substring(0, 512) }
        $entry = [ordered]@{
            timestamp_utc  = (Get-Date).ToUniversalTime().ToString('o')
            run_id         = $script:HeliosTraceRunId
            process_id     = $PID
            tool_use_id    = $script:HeliosTraceToolUseId
            command_sha256 = $script:HeliosTraceCommandSha256
            stage          = $Stage
            elapsed_ms     = [Math]::Round($script:HeliosTraceClock.Elapsed.TotalMilliseconds, 3)
            error_type     = [string]$ErrorType
            error_message  = $message
        }
        $line = $entry | ConvertTo-Json -Depth 3 -Compress
        $traceDir = [System.IO.Path]::GetDirectoryName($script:HeliosTracePath)
        [System.IO.Directory]::CreateDirectory($traceDir) | Out-Null
        [System.IO.File]::AppendAllText($script:HeliosTracePath, $line + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    } catch {}
}

function Write-HeliosHookResponse {
    param([Parameter(Mandatory)][string]$Text)
    Write-HeliosPreToolTrace -Stage 'STDOUT_RESPONSE_START'
    try {
        Write-Output $Text
    } catch {
        $traceError = $_.Exception
        Write-HeliosPreToolTrace -Stage 'STDOUT_RESPONSE_EXCEPTION' -ErrorType $traceError.GetType().FullName -ErrorMessage $traceError.Message
        Write-HeliosPreToolTrace -Stage 'HOOK_PROCESS_EXCEPTION' -ErrorType $traceError.GetType().FullName -ErrorMessage $traceError.Message
        throw
    }
    Write-HeliosPreToolTrace -Stage 'STDOUT_RESPONSE_END'
}

Write-HeliosPreToolTrace -Stage 'HOOK_PROCESS_START'

# --- Wire protocol constants ---

$script:HeliosGateSchemaVersion = 'command-gate.v1'
$script:HeliosSchemaDocVersion  = 'helios-gate-schema.v1'
$script:HeliosSchemaRelPath     = 'schema/helios-gate.schema.json'
$script:HeliosWireHardCap       = 8192

# --- Inline utilities (no external dependencies) ---

function Get-BytesSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash($Bytes)
    return ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Get-TextSha256 {
    param([Parameter(Mandatory)][string]$Text)
    return Get-BytesSha256 -Bytes ([System.Text.Encoding]::UTF8.GetBytes($Text))
}

function Deny {
    param([string]$Reason)
    $Out = @{
        hookSpecificOutput = @{
            hookEventName = 'PreToolUse'
            permissionDecision = 'deny'
            permissionDecisionReason = $Reason
        }
    }
    Write-HeliosHookResponse -Text ($Out | ConvertTo-Json -Depth 5 -Compress)
    Write-HeliosPreToolTrace -Stage 'HOOK_PROCESS_NORMAL_EXIT'
    exit 0
}

function DenyFatal {
    param([string]$Reason)
    Deny $Reason
}

function New-HeliosWireBody {
    param([string]$Op, [string]$Status, [string]$SchemaSha)
    return [ordered]@{
        op                  = $Op
        status              = $Status
        executed            = $false
        gate_schema_version = $script:HeliosGateSchemaVersion
        schema_doc_version  = $script:HeliosSchemaDocVersion
        schema_sha256       = $SchemaSha
        issued_utc          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        truncated           = $false
    }
}

function Send-HeliosWire {
    # Emits a two-line HELIOS/1 envelope as the deny reason and exits. The deny
    # is deliberate: it is what prevents execution. For VIRTUAL <op> OK the
    # envelope IS the answer and the command must not be retried.
    param(
        [Parameter(Mandatory)][string]$Sentinel,
        [Parameter(Mandatory)]$Body,
        [string]$Op = ''
    )
    $json = $Body | ConvertTo-Json -Depth 10 -Compress
    $text = "$Sentinel`n$json"
    if ($text.Length -gt $script:HeliosWireHardCap) {
        $fallbackSentinel = $Sentinel
        if ($Op) { $fallbackSentinel = "HELIOS/1 VIRTUAL $Op ERROR" }
        $fallback = [ordered]@{
            op        = $Op
            status    = 'error'
            executed  = $false
            truncated = $true
            error     = [ordered]@{
                code    = 'OVERSIZE'
                message = 'response exceeded the 8192-byte wire cap; request a narrower projection'
                recover = 'helios gate schema'
            }
        }
        $text = "$fallbackSentinel`n" + ($fallback | ConvertTo-Json -Depth 5 -Compress)
    }
    Deny $text
}

function Write-IntegrityDecision {
    param([string]$SessionId, [string]$ToolUseId, [hashtable]$Data)
    try {
        $dir = Join-Path $GateRoot "evidence\integrity\sessions\$SessionId\commands"
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $path = Join-Path $dir "$ToolUseId.decision.json"
        $Data | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8
    } catch {
        $traceError = $_.Exception
        Write-HeliosPreToolTrace -Stage 'DECISION_WRITE_EXCEPTION' -ErrorType $traceError.GetType().FullName -ErrorMessage $traceError.Message
    }
}

# --- Slim payload normalization ---
# Claude presents Bash/PowerShell with tool_input.command as a string. Codex
# (>= 0.144, confirmed live 2026-07-11) presents its shell tool the same way:
# tool_name 'Bash', tool_input.command string, cwd = shell workdir. The existing
# Claude-compatible path already handles both; no separate Codex adapter exists.
# Effective working directory prefers tool_input.workdir when present, else cwd.

function Get-HeliosCanonicalRequest {
    param([Parameter(Mandatory)]$Payload)

    $execToolNames = @('Bash', 'PowerShell')
    $toolName = ''
    if ($Payload.tool_name) { $toolName = "$($Payload.tool_name)" }

    $req = @{
        tool_name     = $toolName
        is_exec_tool  = ($toolName -in $execToolNames)
        command       = $null
        shell         = $null
        effective_cwd = "$($Payload.cwd)"
        session_id    = "$($Payload.session_id)"
        tool_use_id   = "$($Payload.tool_use_id)"
    }

    $ti = $Payload.tool_input
    if ($ti -and $ti.PSObject -and $ti.PSObject.Properties['workdir'] -and $ti.workdir) {
        $req.effective_cwd = "$($ti.workdir)"
    }

    if ($req.is_exec_tool) {
        $req.shell = $toolName.ToLower()
        if ($ti -and $ti.PSObject -and $ti.PSObject.Properties['command']) {
            if ($ti.command -is [string]) { $req.command = $ti.command }
        }
    }

    return $req
}

# --- Canonical schema + live policy (fail closed; no hardcoded fallback) ---

function Read-HeliosCanonicalSchema {
    param([string]$Root, [hashtable]$ManifestHashes)
    $relPath = $script:HeliosSchemaRelPath
    if (-not $ManifestHashes.ContainsKey($relPath)) {
        throw "canonical schema '$relPath' is not in the protected manifest"
    }
    $fullPath = Join-Path $Root ($relPath -replace '/', '\')
    if (-not (Test-Path $fullPath)) {
        throw "canonical schema missing on disk: $relPath"
    }
    $doc = $null
    try {
        $doc = Get-Content $fullPath -Raw | ConvertFrom-Json
    } catch {
        throw "canonical schema unparseable: $($_.Exception.Message)"
    }
    if (-not $doc.sections -or -not $doc.sections.fields -or
        -not $doc.sections.fields.required_base_fields) {
        throw 'canonical schema malformed: sections.fields.required_base_fields missing'
    }
    return @{ doc = $doc; sha = $ManifestHashes[$relPath] }
}

function Get-HeliosLiveTierFields {
    param([string]$Root, [int]$Tier)
    $policyPath = Join-Path $Root 'policy\command-policy.json'
    if (-not (Test-Path $policyPath)) { throw 'command-policy.json missing' }
    $policy = Get-Content $policyPath -Raw | ConvertFrom-Json
    $key = [string][Math]::Min($Tier, 3)
    $fields = $policy.tier_required_fields.$key
    if (-not $fields) { throw "tier_required_fields['$key'] missing from live policy" }
    return @($fields)
}

# --- Virtual operation grammar (exact; protocol tokens, nothing executes) ---

function Get-HeliosVirtualRequest {
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $t = $Command.Trim()
    if ($t -notmatch '^(?i)helios(\s|$)') { return $null }

    $invalid = @{ valid = $false; op = 'invalid'; code = 'BAD_ARGS'; message = ''; recover = 'helios gate capabilities' }

    if ($t -match '[;&|<>`$()]') {
        $invalid.message = 'virtual commands accept no pipes, redirection, chaining, substitution, or grouping'
        return $invalid
    }

    $tokens = @($t -split '\s+')
    if ($tokens.Count -lt 3 -or $tokens[0].ToLower() -ne 'helios' -or $tokens[1].ToLower() -ne 'gate') {
        $invalid.message = 'unknown virtual command; supported: helios gate <schema|scaffold|version|capabilities>'
        return $invalid
    }

    $op = $tokens[2].ToLower()
    $rest = @()
    if ($tokens.Count -gt 3) { $rest = @($tokens[3..($tokens.Count - 1)]) }

    switch ($op) {
        'version' {
            if ($rest.Count -gt 0) { $invalid.message = "'helios gate version' accepts no arguments"; return $invalid }
            return @{ valid = $true; op = 'version'; args = @{} }
        }
        'capabilities' {
            if ($rest.Count -gt 0) { $invalid.message = "'helios gate capabilities' accepts no arguments"; return $invalid }
            return @{ valid = $true; op = 'capabilities'; args = @{} }
        }
        'schema' {
            $args = @{ tier = $null; shell = $null; example = $false; section = $null; format = $null }
            $i = 0
            while ($i -lt $rest.Count) {
                switch ($rest[$i].ToLower()) {
                    '--format' {
                        if ($i + 1 -ge $rest.Count -or $rest[$i + 1].ToLower() -ne 'json') {
                            $invalid.message = "--format supports only 'json'"; return $invalid
                        }
                        $args.format = 'json'; $i += 2
                    }
                    '--tier' {
                        if ($i + 1 -ge $rest.Count -or $rest[$i + 1] -notmatch '^[0-3]$') {
                            $invalid.message = '--tier requires a value 0-3'; return $invalid
                        }
                        $args.tier = [int]$rest[$i + 1]; $i += 2
                    }
                    '--shell' {
                        if ($i + 1 -ge $rest.Count -or $rest[$i + 1].ToLower() -notin @('bash', 'powershell')) {
                            $invalid.message = '--shell requires bash or powershell'; return $invalid
                        }
                        $args.shell = $rest[$i + 1].ToLower(); $i += 2
                    }
                    '--example' { $args.example = $true; $i += 1 }
                    '--section' {
                        if ($i + 1 -ge $rest.Count) { $invalid.message = '--section requires a section name'; return $invalid }
                        $args.section = $rest[$i + 1].ToLower(); $i += 2
                    }
                    default { $invalid.message = "unrecognized argument '$($rest[$i])'"; return $invalid }
                }
            }
            if (($null -ne $args.tier) -xor ($null -ne $args.shell)) {
                $invalid.message = '--tier and --shell must be provided together'; return $invalid
            }
            if ($args.example -and $null -eq $args.tier) {
                $invalid.message = '--example requires --tier and --shell'; return $invalid
            }
            if ($args.section -and $null -ne $args.tier) {
                $invalid.message = '--section cannot be combined with --tier/--shell'; return $invalid
            }
            return @{ valid = $true; op = 'schema'; args = $args }
        }
        'scaffold' {
            $args = @{ blocked_id = $null }
            if ($rest.Count -eq 0) { return @{ valid = $true; op = 'scaffold'; args = $args } }
            if ($rest.Count -eq 2 -and $rest[0].ToLower() -eq '--blocked-id') {
                $args.blocked_id = $rest[1]
                return @{ valid = $true; op = 'scaffold'; args = $args }
            }
            $invalid.message = "scaffold accepts no arguments or '--blocked-id <id>'"
            return $invalid
        }
        default {
            $invalid.message = "unknown operation '$op'; supported: schema, scaffold, version, capabilities"
            return $invalid
        }
    }
}

# --- Scaffold: session-bound blocked-record resolution ---

function Resolve-HeliosBlockedRecord {
    param([string]$Root, [string]$BlockedId, [string]$SessionId)

    $blockedDir = Join-Path $Root 'blocked'
    $ttlMinutes = 30
    $fail = { param($code, $msg, $recover)
        return @{ ok = $false; code = $code; message = $msg; recover = $recover }
    }

    if ($BlockedId) {
        if ($BlockedId -notmatch '^\d{8}-\d{6}-[a-f0-9]{12}(-[A-Za-z0-9_-]{1,24})?$') {
            return (& $fail 'BAD_ID' "blocked id '$BlockedId' does not match the blocked-record grammar" 'helios gate scaffold')
        }
        $candidate = Join-Path $blockedDir "$BlockedId.blocked.json"
        $resolved = [System.IO.Path]::GetFullPath($candidate)
        $resolvedRoot = [System.IO.Path]::GetFullPath($blockedDir) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            return (& $fail 'BAD_ID' 'blocked id resolves outside the blocked directory' 'helios gate scaffold')
        }
        if (-not (Test-Path $resolved -PathType Leaf)) {
            return (& $fail 'NOT_FOUND' "no blocked record '$BlockedId'" 'rerun the original command so Helios mints a fresh blocked record, then scaffold again')
        }
        $attrs = [System.IO.File]::GetAttributes($resolved)
        if ($attrs -band [System.IO.FileAttributes]::ReparsePoint) {
            return (& $fail 'BAD_ID' 'blocked record is a reparse point' 'helios gate scaffold')
        }
        $record = $null
        try { $record = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json } catch {
            return (& $fail 'NOT_FOUND' 'blocked record unparseable' 'rerun the original command so Helios mints a fresh blocked record')
        }
        if (-not $record.session_id) {
            return (& $fail 'STALE_RECORD' 'blocked record predates session binding and cannot be scaffolded' 'rerun the original command so Helios creates a fresh session-bound blocked record')
        }
        if ("$($record.session_id)" -ne $SessionId) {
            return (& $fail 'SESSION_MISMATCH' 'blocked record belongs to a different session' 'rerun the original command in this session, then scaffold the new blocked id')
        }
        try {
            $age = ((Get-Date).ToUniversalTime() - [DateTime]::Parse($record.timestamp_utc).ToUniversalTime()).TotalMinutes
            if ($age -gt $ttlMinutes) {
                return (& $fail 'EXPIRED' "blocked record is older than $ttlMinutes minutes" 'rerun the original command so Helios mints a fresh blocked record')
            }
        } catch {
            return (& $fail 'EXPIRED' 'blocked record timestamp unparseable' 'rerun the original command so Helios mints a fresh blocked record')
        }
        return @{ ok = $true; id = $BlockedId; record = $record }
    }

    # Bare scaffold: newest in-TTL record for this session.
    $best = $null
    $bestId = $null
    $bestTime = [DateTime]::MinValue
    foreach ($f in (Get-ChildItem $blockedDir -Filter '*.blocked.json' -File -ErrorAction SilentlyContinue)) {
        $rec = $null
        try { $rec = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json } catch { continue }
        if (-not $rec.session_id -or "$($rec.session_id)" -ne $SessionId) { continue }
        $ts = [DateTime]::MinValue
        try { $ts = [DateTime]::Parse($rec.timestamp_utc).ToUniversalTime() } catch { continue }
        if (((Get-Date).ToUniversalTime() - $ts).TotalMinutes -gt $ttlMinutes) { continue }
        if ($ts -gt $bestTime) {
            $bestTime = $ts
            $best = $rec
            $bestId = $f.Name -replace '\.blocked\.json$', ''
        }
    }
    if ($null -eq $best) {
        return (& $fail 'NOT_FOUND' 'no in-TTL blocked record for this session' 'rerun the original command so Helios mints a fresh blocked record, then scaffold again')
    }
    return @{ ok = $true; id = $bestId; record = $best }
}

# --- Virtual operation executor ---

function Invoke-HeliosVirtualOperation {
    param(
        [Parameter(Mandatory)]$Request,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][hashtable]$ManifestHashes,
        [string]$SessionId,
        [string]$ToolUseId
    )

    $schema = Read-HeliosCanonicalSchema -Root $Root -ManifestHashes $ManifestHashes
    $doc = $schema.doc
    $sha = $schema.sha
    $op = $Request.op

    if (-not $Request.valid) {
        $body = New-HeliosWireBody -Op 'invalid' -Status 'error' -SchemaSha $sha
        $body.error = [ordered]@{ code = $Request.code; message = $Request.message; recover = $Request.recover }
        return @{ sentinel = 'HELIOS/1 VIRTUAL invalid ERROR'; body = $body; verdict = 'VIRTUAL_ERROR'; op = 'invalid' }
    }

    $body = New-HeliosWireBody -Op $op -Status 'ok' -SchemaSha $sha
    $body.note = 'Introspection answered by the gate itself; no process ran, no gate was consumed. Do not retry this command.'

    switch ($op) {
        'version' {
            $body.result = [ordered]@{
                gate_schema_version = $script:HeliosGateSchemaVersion
                schema_doc_version  = $script:HeliosSchemaDocVersion
                wire_protocol       = 'HELIOS/1'
                schema_sha256       = $sha
            }
            return @{ sentinel = 'HELIOS/1 VIRTUAL version OK'; body = $body; verdict = 'VIRTUAL_OK'; op = $op }
        }
        'capabilities' {
            $body.result = [ordered]@{
                operations = @($doc.sections.virtual.operations)
                grammar    = @($doc.sections.virtual.grammar)
                rules      = $doc.sections.virtual.rules
            }
            return @{ sentinel = 'HELIOS/1 VIRTUAL capabilities OK'; body = $body; verdict = 'VIRTUAL_OK'; op = $op }
        }
        'schema' {
            $args = $Request.args
            if ($args.section) {
                $sectionProp = $doc.sections.PSObject.Properties[$args.section]
                if (-not $sectionProp) {
                    $names = @($doc.sections.PSObject.Properties | ForEach-Object { $_.Name })
                    $err = New-HeliosWireBody -Op $op -Status 'error' -SchemaSha $sha
                    $err.error = [ordered]@{
                        code = 'BAD_ARGS'
                        message = "unknown section '$($args.section)'; known: $($names -join ', ')"
                        recover = 'helios gate schema'
                    }
                    return @{ sentinel = 'HELIOS/1 VIRTUAL schema ERROR'; body = $err; verdict = 'VIRTUAL_ERROR'; op = $op }
                }
                $body.result = [ordered]@{ section = $args.section; content = $sectionProp.Value }
                $body.next = 'helios gate schema'
                return @{ sentinel = 'HELIOS/1 VIRTUAL schema OK'; body = $body; verdict = 'VIRTUAL_OK'; op = $op }
            }
            if ($null -ne $args.tier) {
                $tierFields = Get-HeliosLiveTierFields -Root $Root -Tier $args.tier
                $suffixProp = $doc.sections.enums.exit_capture_suffixes.PSObject.Properties[$args.shell]
                $result = [ordered]@{
                    tier                   = $args.tier
                    shell                  = $args.shell
                    required_base_fields   = @($doc.sections.fields.required_base_fields)
                    tier_required_fields   = @($tierFields)
                    exit_capture_modes     = @($doc.sections.enums.exit_capture)
                    exit_capture_reasons   = @($doc.sections.enums.exit_capture_reason)
                    exit_capture_suffixes  = @($suffixProp.Value)
                    segments_contract      = $doc.sections.segments.contract
                    chain_contract         = $doc.sections.chain.contract
                }
                if ($args.tier -ge 3) { $result.impact_contract = $doc.sections.impact.contract }
                if ($args.example) {
                    $result.example = $doc.sections.examples.tier_1_bash
                    $result.example_note = 'adjust command/shell/tier fields to the denied command; tier>=2 adds stop_conditions, tier 3 adds read_write_impact'
                } else {
                    $body.next = "helios gate schema --tier $($args.tier) --shell $($args.shell) --example"
                }
                $body.result = $result
                return @{ sentinel = 'HELIOS/1 VIRTUAL schema OK'; body = $body; verdict = 'VIRTUAL_OK'; op = $op }
            }
            # Bare (or --format json): index only, never the full document.
            $sections = @()
            foreach ($p in $doc.sections.PSObject.Properties) {
                $len = ($p.Value | ConvertTo-Json -Depth 10 -Compress).Length
                $sections += [ordered]@{ name = $p.Name; bytes = $len }
            }
            $body.result = [ordered]@{
                index    = $sections
                queries  = @(
                    'helios gate schema --tier <0-3> --shell <bash|powershell> [--example]',
                    'helios gate schema --section <name>',
                    'helios gate version',
                    'helios gate capabilities',
                    'helios gate scaffold [--blocked-id <id>]'
                )
            }
            $body.next = 'helios gate schema --section fields'
            return @{ sentinel = 'HELIOS/1 VIRTUAL schema OK'; body = $body; verdict = 'VIRTUAL_OK'; op = $op }
        }
        'scaffold' {
            $res = Resolve-HeliosBlockedRecord -Root $Root -BlockedId $Request.args.blocked_id -SessionId $SessionId
            if (-not $res.ok) {
                $err = New-HeliosWireBody -Op $op -Status 'error' -SchemaSha $sha
                $err.error = [ordered]@{ code = $res.code; message = $res.message; recover = $res.recover }
                return @{ sentinel = 'HELIOS/1 VIRTUAL scaffold ERROR'; body = $err; verdict = 'VIRTUAL_ERROR'; op = $op }
            }
            $rec = $res.record

            . (Join-Path $Root 'hooks\command_decomposer.ps1')
            $decomp = Get-CommandDecomposition -Command "$($rec.command)"
            $segments = @($decomp.segments_detected)
            $multi = ($segments.Count -gt 1)

            $tier = 0
            if ($null -ne $rec.detected_tier) { $tier = [int]$rec.detected_tier }
            elseif ($null -ne $rec.tier) { $tier = [int]$rec.tier }

            $now = (Get-Date).ToUniversalTime()
            $gate = [ordered]@{
                schema_version    = $script:HeliosGateSchemaVersion
                correlation_id    = ''
                created_utc       = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
                expires_utc       = $now.AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
                command           = "$($rec.command)"
                command_sha256    = "$($rec.command_sha256)"
                working_directory = "$($rec.working_directory)"
                shell             = "$($rec.shell)"
                risk_tier         = $tier
                exit_capture      = ''
                multi_command     = $multi
                segments          = $segments
                need              = ''
                expected          = ''
                actual_means      = ''
                next_logic        = ''
                approval_boundary = ''
            }
            # Destination discovery: build the pending path from the front
            # controller's OWN gate root ($Root), never from blocked-record
            # contents or the caller's working directory. This lets an agent that
            # has never seen the Helios root learn exactly where to write.
            $pendingDir = Join-Path $Root 'pending'
            $body.result = [ordered]@{
                gate     = $gate
                gate_root               = "$Root"
                pending_directory       = "$pendingDir"
                suggested_gate_filename = '<correlation-id>.gate.json'
                suggested_gate_path     = (Join-Path $pendingDir '<correlation-id>.gate.json')
                write_instruction       = 'Complete the unresolved semantic fields, then write the gate JSON to suggested_gate_path (an absolute path inside the Helios gate root). Do NOT write it relative to the current working directory.'
                observed = [ordered]@{
                    working_directory = "$($rec.working_directory)"
                    shell             = "$($rec.shell)"
                    command_sha256    = "$($rec.command_sha256)"
                    detected_tier     = $tier
                    session_id        = "$($rec.session_id)"
                    tool_use_id       = "$($rec.tool_use_id)"
                    last_correlation_id = "$($rec.last_correlation_id)"
                }
                unresolved = @('need', 'expected', 'actual_means', 'next_logic', 'stop_conditions', 'read_write_impact', 'approval_boundary', 'exit_capture', 'previous_correlation_id OR new_chain')
                caution  = 'Retry must execute with the same effective working directory (for Codex: the same workdir). If exit_capture=suffix, append an approved suffix to the command and recompute command_sha256 and segments - the prefilled values reflect the originally blocked command. Write the completed gate to pending/ yourself; this scaffold authorizes nothing.'
            }
            return @{ sentinel = 'HELIOS/1 VIRTUAL scaffold OK'; body = $body; verdict = 'VIRTUAL_OK'; op = $op }
        }
    }

    $err = New-HeliosWireBody -Op $op -Status 'error' -SchemaSha $sha
    $err.error = [ordered]@{ code = 'BAD_ARGS'; message = "unhandled operation '$op'"; recover = 'helios gate capabilities' }
    return @{ sentinel = "HELIOS/1 VIRTUAL $op ERROR"; body = $err; verdict = 'VIRTUAL_ERROR'; op = $op }
}

# --- Dot-source guard: export functions only ---
if ($HeliosDotSourceFunctionsOnly) { return }

trap {
    $traceError = $_.Exception
    $traceType = ''
    $traceMessage = ''
    if ($null -ne $traceError) {
        $traceType = $traceError.GetType().FullName
        $traceMessage = $traceError.Message
    }
    Write-HeliosPreToolTrace -Stage 'HOOK_PROCESS_EXCEPTION' -ErrorType $traceType -ErrorMessage $traceMessage
    break
}

# --- Step 1: Read stdin ---

Write-HeliosPreToolTrace -Stage 'INPUT_PARSE_START'
$RawInput = $null
try {
    $RawInput = [Console]::In.ReadToEnd()
} catch {
    $traceError = $_.Exception
    Write-HeliosPreToolTrace -Stage 'HOOK_PROCESS_EXCEPTION' -ErrorType $traceError.GetType().FullName -ErrorMessage $traceError.Message
    DenyFatal 'Cannot read stdin'
}

if ([string]::IsNullOrWhiteSpace($RawInput)) {
    DenyFatal 'Empty stdin'
}

$Payload = $null
try {
    $Payload = $RawInput | ConvertFrom-Json
} catch {
    $traceError = $_.Exception
    Write-HeliosPreToolTrace -Stage 'HOOK_PROCESS_EXCEPTION' -ErrorType $traceError.GetType().FullName -ErrorMessage $traceError.Message
    DenyFatal "Cannot parse hook payload: $($_.Exception.Message)"
}
Write-HeliosPreToolTrace -Stage 'INPUT_PARSE_END'

# --- Step 2: Non-shell passthrough + normalization ---

Write-HeliosPreToolTrace -Stage 'CANONICALIZATION_START'
$Canonical = Get-HeliosCanonicalRequest -Payload $Payload
$script:HeliosTraceToolUseId = [string]$Canonical.tool_use_id

if (-not $Canonical.is_exec_tool) {
    Write-HeliosPreToolTrace -Stage 'CANONICALIZATION_END'
    Write-HeliosHookResponse -Text '{}'
    Write-HeliosPreToolTrace -Stage 'HOOK_PROCESS_NORMAL_EXIT'
    exit 0
}

$ToolName   = $Canonical.tool_name
$SessionId  = $Canonical.session_id
$ToolUseId  = $Canonical.tool_use_id
$Cwd        = $Canonical.effective_cwd
$Shell      = $Canonical.shell
$Command    = $Canonical.command

$CommandHash = ''
if ($Command) {
    $CommandHash = Get-TextSha256 -Text $Command
}
$script:HeliosTraceCommandSha256 = $CommandHash
Write-HeliosPreToolTrace -Stage 'CANONICALIZATION_END'

# --- Step 3: Locate manifest ---

Write-HeliosPreToolTrace -Stage 'CONTROL_PLANE_INTEGRITY_START'
$ManifestPath = Join-Path $GateRoot 'manifest\helios-envelope.json'
$SidecarPath  = Join-Path $GateRoot 'manifest\helios-envelope.sha256'

if (-not (Test-Path $ManifestPath) -or -not (Test-Path $SidecarPath)) {
    Write-IntegrityDecision -SessionId $SessionId -ToolUseId $ToolUseId -Data @{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
        verdict       = 'INTEGRITY_FAILURE'
        reason        = 'Manifest files missing'
        session_id    = $SessionId
        tool_use_id   = $ToolUseId
    }
    DenyFatal 'INTEGRITY: manifest files missing'
}

# --- Step 4: Sidecar verification ---

$ManifestBytes = [System.IO.File]::ReadAllBytes($ManifestPath)
$ManifestHash  = Get-BytesSha256 -Bytes $ManifestBytes
$SidecarHash   = ([System.IO.File]::ReadAllText($SidecarPath)).Trim().ToLower()

if ($ManifestHash -ne $SidecarHash) {
    Write-IntegrityDecision -SessionId $SessionId -ToolUseId $ToolUseId -Data @{
        timestamp_utc    = (Get-Date).ToUniversalTime().ToString('o')
        verdict          = 'INTEGRITY_FAILURE'
        reason           = 'Manifest sidecar mismatch'
        computed_hash    = $ManifestHash
        sidecar_hash     = $SidecarHash
        session_id       = $SessionId
        tool_use_id      = $ToolUseId
        command_sha256   = $CommandHash
    }
    Send-HeliosWire -Sentinel 'HELIOS/1 DENY INTEGRITY_DRIFT' -Body ([ordered]@{
        code     = 'INTEGRITY_DRIFT'
        message  = "Manifest sidecar mismatch (computed=$ManifestHash sidecar=$SidecarHash). Helios does not accept changed protected files as a new baseline."
        recovery = 'Use the Akashic Helios runtime reset, restore, or rebaseline workflow (helios-integrity-adapter tools) after human review.'
    })
}

# --- Step 5: Parse manifest ---

$Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json

$ManifestHashes = @{}
foreach ($prop in $Manifest.protected.hashes.PSObject.Properties) {
    $ManifestHashes[$prop.Name] = $prop.Value
}

# --- Step 6-7: Verify all protected file hashes ---

$DriftedFiles = @()
foreach ($relPath in $ManifestHashes.Keys) {
    $fullPath = Join-Path $GateRoot $relPath
    if (-not (Test-Path $fullPath)) {
        $DriftedFiles += @{ path = $relPath; reason = 'MISSING'; expected = $ManifestHashes[$relPath]; actual = $null }
        continue
    }
    $fileBytes = [System.IO.File]::ReadAllBytes($fullPath)
    $fileHash  = Get-BytesSha256 -Bytes $fileBytes
    if ($fileHash -ne $ManifestHashes[$relPath]) {
        $DriftedFiles += @{ path = $relPath; reason = 'HASH_MISMATCH'; expected = $ManifestHashes[$relPath]; actual = $fileHash }
    }
}

# --- Step 8: On drift, FAIL CLOSED and direct recovery to Akashic ---
# Helios has no internal rebaseline authority. It never rewrites its own
# manifest or accepts drifted protected files. Akashic owns runtime changes.

if ($DriftedFiles.Count -gt 0) {
    $driftPaths = ($DriftedFiles | ForEach-Object { $_.path }) -join ', '
    $driftPathList = @($DriftedFiles | ForEach-Object { $_.path })

    try {
        $beforeDir = Join-Path $GateRoot "evidence\integrity\sessions\$SessionId\commands"
        if (-not (Test-Path $beforeDir)) { New-Item -ItemType Directory -Path $beforeDir -Force | Out-Null }
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $beforeData = @{
            timestamp_utc  = (Get-Date).ToUniversalTime().ToString('o')
            session_id     = $SessionId
            tool_use_id    = $ToolUseId
            command_sha256 = $CommandHash
            drifted_files  = $DriftedFiles
            integrity_status = 'DRIFT'
        }
        $beforePath = Join-Path $beforeDir "$ToolUseId.before.json"
        [System.IO.File]::WriteAllText($beforePath, ($beforeData | ConvertTo-Json -Depth 5), $Utf8NoBom)
    } catch {}

    Write-IntegrityDecision -SessionId $SessionId -ToolUseId $ToolUseId -Data @{
        timestamp_utc    = (Get-Date).ToUniversalTime().ToString('o')
        verdict          = 'INTEGRITY_FAILURE'
        reason           = "Protected envelope drift: $driftPaths"
        drifted_files    = $DriftedFiles
        session_id       = $SessionId
        tool_use_id      = $ToolUseId
        command_sha256   = $CommandHash
    }
    Send-HeliosWire -Sentinel 'HELIOS/1 DENY INTEGRITY_DRIFT' -Body ([ordered]@{
        code     = 'INTEGRITY_DRIFT'
        drifted  = $driftPathList
        message  = "Protected envelope drift detected in: $driftPaths. Helios does not accept changed protected files as a new baseline."
        recovery = 'Use the Akashic Helios runtime reset, restore, or rebaseline workflow (helios-integrity-adapter tools) after human review.'
    })
}

# --- Step 9-10: Bridge is verified — dot-source it ---

. (Join-Path $GateRoot 'hooks\lib\HeliosIntegrityBridge.ps1')

# --- Step 11: Session baseline ---

$BaselinePath  = Join-Path $GateRoot "evidence\integrity\sessions\$SessionId\baseline.json"
$BaselineHashes = $null

if (-not (Test-Path $BaselinePath)) {
    $BaselineResult = New-HeliosSessionBaseline `
        -GateRoot $GateRoot -ManifestHashes $ManifestHashes `
        -SessionId $SessionId -ToolUseId $ToolUseId `
        -CommandSha256 $CommandHash -Cwd $Cwd -Shell $Shell

    if (-not $BaselineResult.created) {
        Write-IntegrityDecision -SessionId $SessionId -ToolUseId $ToolUseId -Data @{
            timestamp_utc  = (Get-Date).ToUniversalTime().ToString('o')
            verdict        = 'INTEGRITY_FAILURE'
            reason         = "Cannot create session baseline: $($BaselineResult.reason)"
            session_id     = $SessionId
            tool_use_id    = $ToolUseId
            command_sha256 = $CommandHash
        }
        DenyFatal "INTEGRITY: cannot create session baseline: $($BaselineResult.reason)"
    }
    $BaselineHashes = $BaselineResult.baseline.protected_hashes
} else {
    $BaselineJson = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $BaselineHashes = @{}
    foreach ($prop in $BaselineJson.protected_hashes.PSObject.Properties) {
        $BaselineHashes[$prop.Name] = $prop.Value
    }
}

# --- Step 12: Compare current state against durable manifest and session baseline ---

$Snapshot = Get-HeliosEnvelopeSnapshot `
    -GateRoot $GateRoot -ManifestHashes $ManifestHashes `
    -SessionId $SessionId -ToolUseId $ToolUseId `
    -CommandSha256 $CommandHash -Cwd $Cwd -Shell $Shell

$ProtectedResult = Compare-HeliosProtectedEnvelope `
    -CurrentSnapshot $Snapshot -ManifestHashes $ManifestHashes `
    -BaselineHashes $BaselineHashes

if ($ProtectedResult.verdict -ne 'CLEAN') {
    $driftDetails = @($ProtectedResult.details | Where-Object { $_.drift_source.Count -gt 0 })
    $driftPaths = ($driftDetails | ForEach-Object { $_.path }) -join ', '

    Write-HeliosIntegrityEvidence -GateRoot $GateRoot -SessionId $SessionId -ToolUseId $ToolUseId `
        -EvidenceType 'before' -Data @{
            timestamp_utc    = (Get-Date).ToUniversalTime().ToString('o')
            session_id       = $SessionId
            tool_use_id      = $ToolUseId
            command_sha256   = $CommandHash
            protected        = $Snapshot.protected
            mutable          = $Snapshot.mutable
            context          = $Snapshot.context
            integrity_status = 'DRIFT'
        } | Out-Null

    Write-IntegrityDecision -SessionId $SessionId -ToolUseId $ToolUseId -Data @{
        timestamp_utc    = (Get-Date).ToUniversalTime().ToString('o')
        verdict          = 'INTEGRITY_FAILURE'
        reason           = "Protected envelope drift (baseline comparison): $driftPaths"
        drift_details    = $driftDetails
        session_id       = $SessionId
        tool_use_id      = $ToolUseId
        command_sha256   = $CommandHash
    }
    Send-HeliosWire -Sentinel 'HELIOS/1 DENY INTEGRITY_DRIFT' -Body ([ordered]@{
        code     = 'INTEGRITY_DRIFT'
        drifted  = @($driftDetails | ForEach-Object { $_.path })
        message  = "Protected envelope drift (vs baseline and/or manifest): $driftPaths"
        recovery = 'Use the Akashic Helios runtime reset, restore, or rebaseline workflow (helios-integrity-adapter tools) after human review.'
    })
}

# --- Step 12b: Load session_continuity (verified) for corridor + continuity ---
Write-HeliosPreToolTrace -Stage 'CONTROL_PLANE_INTEGRITY_END'
$SCPath = Join-Path $GateRoot 'hooks\session_continuity.ps1'
if (Test-Path $SCPath) { . $SCPath }

# --- Step 12c: Virtual introspection corridor ---
# Runs only after the full integrity chain is CLEAN, before any snapshot, before
# the pretooluse_seen ledger entry, before gate_check loads, before any pending
# gate can be consumed. Answered via deny: nothing executes.

if ([string]::IsNullOrWhiteSpace($Command)) {
    DenyFatal 'No command field in tool_input'
}

$VirtualReq = Get-HeliosVirtualRequest -Command $Command
if ($null -ne $VirtualReq) {
    $VirtualResponse = $null
    try {
        $VirtualResponse = Invoke-HeliosVirtualOperation -Request $VirtualReq -Root $GateRoot `
            -ManifestHashes $ManifestHashes -SessionId $SessionId -ToolUseId $ToolUseId
    } catch {
        Write-IntegrityDecision -SessionId $SessionId -ToolUseId $ToolUseId -Data @{
            timestamp_utc  = (Get-Date).ToUniversalTime().ToString('o')
            verdict        = 'INTEGRITY_FAILURE'
            reason         = "Virtual operation failed closed: $($_.Exception.Message)"
            session_id     = $SessionId
            tool_use_id    = $ToolUseId
            command_sha256 = $CommandHash
        }
        DenyFatal "INTEGRITY: $($_.Exception.Message)"
    }

    $wireJson = $VirtualResponse.body | ConvertTo-Json -Depth 10 -Compress
    $responseSha = Get-TextSha256 -Text "$($VirtualResponse.sentinel)`n$wireJson"

    Write-IntegrityDecision -SessionId $SessionId -ToolUseId $ToolUseId -Data @{
        timestamp_utc    = (Get-Date).ToUniversalTime().ToString('o')
        verdict          = $VirtualResponse.verdict
        reason           = "$($VirtualResponse.sentinel) (op=$($VirtualResponse.op))"
        operation        = $VirtualResponse.op
        response_sha256  = $responseSha
        session_id       = $SessionId
        tool_use_id      = $ToolUseId
        command_sha256   = $CommandHash
        integrity_status = 'CLEAN'
    }

    try {
        if (Get-Command Write-SessionLedgerEntry -ErrorAction SilentlyContinue) {
            Write-SessionLedgerEntry -GateRoot $GateRoot -SessionId $SessionId `
                -EventType 'virtual_op_answered' -Data @{
                    operation       = $VirtualResponse.op
                    arguments       = ($Command.Trim())
                    response_sha256 = $responseSha
                    tool_use_id     = $ToolUseId
                    executed        = $false
                }
        }
    } catch {}

    Send-HeliosWire -Sentinel $VirtualResponse.sentinel -Body $VirtualResponse.body -Op $VirtualResponse.op
}

# --- Step 13: Write before snapshot ---

Write-HeliosPreToolTrace -Stage 'BEFORE_SNAPSHOT_WRITE_START'
$ControlPlaneSnapshot = $null
$CPWatcherPath = Join-Path $GateRoot 'hooks\control_plane_watcher.ps1'
try {
    if (Test-Path $CPWatcherPath) {
        . $CPWatcherPath
        $ControlPlaneSnapshot = Get-ControlPlaneSnapshot -GateRoot $GateRoot
    }
} catch {}

# --- Step 13b: Session continuity check ---
# virtual_op_answered is continuity-neutral: it is deliberately absent from the
# break conditions below and never becomes a chain predecessor.
$ContinuityBreak = $false
try {
    if (Get-Command Get-SessionLedger -ErrorAction SilentlyContinue) {
        $LedgerEntries = Get-SessionLedger -GateRoot $GateRoot -SessionId $SessionId
        if ($LedgerEntries.Count -gt 0) {
            $lastEntry = $LedgerEntries[$LedgerEntries.Count - 1]
            if ($lastEntry.event_type -eq 'pretooluse_seen' -or $lastEntry.event_type -eq 'gate_consumed') {
                $ContinuityBreak = $true
            }
        }

        $policyHashForLedger = $null
        try {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $plPath = Join-Path $GateRoot 'policy\command-policy.json'
            if (Test-Path $plPath) {
                $plBytes = [System.IO.File]::ReadAllBytes($plPath)
                $policyHashForLedger = ($sha.ComputeHash($plBytes) | ForEach-Object { $_.ToString('x2') }) -join ''
            }
        } catch {}

        Write-SessionLedgerEntry -GateRoot $GateRoot -SessionId $SessionId `
            -EventType 'pretooluse_seen' -Data @{
                command_sha256     = $CommandHash
                tool_use_id        = $ToolUseId
                policy_hash        = $policyHashForLedger
                continuity_break   = $ContinuityBreak
            }
    }
} catch {}

Write-HeliosIntegrityEvidence -GateRoot $GateRoot -SessionId $SessionId -ToolUseId $ToolUseId `
    -EvidenceType 'before' -Data @{
        timestamp_utc          = (Get-Date).ToUniversalTime().ToString('o')
        session_id             = $SessionId
        tool_use_id            = $ToolUseId
        command_sha256         = $CommandHash
        protected              = $Snapshot.protected
        mutable                = $Snapshot.mutable
        context                = $Snapshot.context
        integrity_status       = 'CLEAN'
        control_plane_snapshot = $ControlPlaneSnapshot
        continuity_break       = $ContinuityBreak
    } | Out-Null

Write-HeliosPreToolTrace -Stage 'BEFORE_SNAPSHOT_WRITE_END'

# --- Step 14: Load tier_classifier and gate_check (both now verified) ---

Write-HeliosPreToolTrace -Stage 'GATE_CHECK_START'
try {
    . (Join-Path $GateRoot 'hooks\tier_classifier.ps1')

    $script:HeliosFrontControllerActive = $true
    $script:HeliosWireContext = @{
        schema_sha256 = $ManifestHashes[$script:HeliosSchemaRelPath]
        effective_cwd = $Cwd
        tool_name     = $ToolName
    }
    . (Join-Path $GateRoot 'hooks\gate_check.ps1')

    # gate_check.ps1 overrides DenyFatal with Write-Error + exit 2, which does not
    # produce deny JSON on stdout. Re-apply front controller's version.
    function DenyFatal { param([string]$Reason); Deny $Reason }

    $GateResult = Invoke-GateValidation -Payload $Payload
} catch {
    $traceError = $_.Exception
    Write-HeliosPreToolTrace -Stage 'GATE_CHECK_EXCEPTION' -ErrorType $traceError.GetType().FullName -ErrorMessage $traceError.Message
    throw
}
Write-HeliosPreToolTrace -Stage 'GATE_CHECK_END'

# --- Step 15: Write decision evidence ---

Write-HeliosPreToolTrace -Stage 'DECISION_BUILD_START'
$DecisionVerdict = switch ($GateResult.action) {
    'allow'       { 'ALLOW' }
    'deny'        { 'DENY' }
    'fatal'       { 'DENY_FATAL' }
    'passthrough' { 'PASSTHROUGH' }
    default       { 'UNKNOWN' }
}

$DecisionEvidence = @{
    timestamp_utc    = (Get-Date).ToUniversalTime().ToString('o')
    verdict          = $DecisionVerdict
    reason           = if ($GateResult.reason) { $GateResult.reason } elseif ($GateResult.message) { $GateResult.message } else { $null }
    command_sha256   = $GateResult.hash
    tier             = $GateResult.tier
    correlation_id   = $GateResult.correlation_id
    integrity_status = 'CLEAN'
    session_id       = $SessionId
    tool_use_id      = $ToolUseId
}
Write-HeliosPreToolTrace -Stage 'DECISION_BUILD_END'

Write-HeliosPreToolTrace -Stage 'DECISION_WRITE_START'
Write-IntegrityDecision -SessionId $SessionId -ToolUseId $ToolUseId -Data $DecisionEvidence
Write-HeliosPreToolTrace -Stage 'DECISION_WRITE_END'
try {
    if (Get-Command Write-SessionLedgerEntry -ErrorAction SilentlyContinue) {
        Write-SessionLedgerEntry -GateRoot $GateRoot -SessionId $SessionId `
            -EventType 'gate_consumed' -Data @{
                correlation_id = $GateResult.correlation_id
                command_sha256 = $GateResult.hash
                declared_tier  = $GateResult.tier
                tool_use_id    = $ToolUseId
                verdict        = $DecisionVerdict
            }
    }
} catch {}

# --- Step 16: Exit with appropriate behavior ---

switch ($GateResult.action) {
    'passthrough' {
        Write-HeliosHookResponse -Text '{}'
        Write-HeliosPreToolTrace -Stage 'HOOK_PROCESS_NORMAL_EXIT'
        exit 0
    }
    'allow' {
        Write-HeliosHookResponse -Text '{}'
        Write-HeliosPreToolTrace -Stage 'HOOK_PROCESS_NORMAL_EXIT'
        exit 0
    }
    'deny'        { $denyMsg = if ($GateResult.display) { $GateResult.display } else { $GateResult.reason }; Deny $denyMsg }
    'fatal'       { DenyFatal $GateResult.message }
    default       { DenyFatal "Unexpected gate result: $($GateResult.action)" }
}
