# evidence_capture.ps1 — PostToolUse and PostToolUseFailure hook
# Captures what happened after a shell command executed (or failed).
# Best-effort — never blocks (exit 0 always).

$ErrorActionPreference = 'SilentlyContinue'

$GateRoot = Split-Path $PSScriptRoot -Parent

function Get-Sha256 {
    param([string]$Text)
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    $HashBytes = $Sha.ComputeHash($Bytes)
    return ($HashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Parse-ExitMarker {
    param([string]$Stdout, [string]$Stderr)
    # Parse EXIT=<number> from stdout or stderr (last occurrence wins)
    $Combined = ''
    if ($Stdout) { $Combined += $Stdout }
    if ($Stderr) { $Combined += "`n" + $Stderr }
    $Matches = [regex]::Matches($Combined, 'EXIT=(\d+)')
    if ($Matches.Count -gt 0) {
        return [int]$Matches[$Matches.Count - 1].Groups[1].Value
    }
    return $null
}

# --- MAIN ---

$RawInput = $null
try {
    $RawInput = [Console]::In.ReadToEnd()
} catch {
    Write-Output '{}'
    exit 0
}

if ([string]::IsNullOrWhiteSpace($RawInput)) {
    Write-Output '{}'
    exit 0
}

$Payload = $null
try {
    $Payload = $RawInput | ConvertFrom-Json
} catch {
    Write-Output '{}'
    exit 0
}

$ToolName = $Payload.tool_name
if ($ToolName -notin @('Bash', 'PowerShell')) {
    Write-Output '{}'
    exit 0
}

$HookEvent = $Payload.hook_event_name
$Command = $null
if ($Payload.tool_input -and $Payload.tool_input.command) {
    $Command = $Payload.tool_input.command
}
if ([string]::IsNullOrWhiteSpace($Command)) {
    Write-Output '{}'
    exit 0
}

$Hash = Get-Sha256 $Command
$ToolUseId = $Payload.tool_use_id
$SessionId = $Payload.session_id
$PayloadCwd = $Payload.cwd
$DurationMs = $Payload.duration_ms
$NowUtc = (Get-Date).ToUniversalTime()
$DatePrefix = $NowUtc.ToString('yyyyMMdd')

# Extract tool_response fields (discovered from debug payload)
$ToolResponse = $Payload.tool_response
$Stdout = $null
$Stderr = $null
$NativeExitCode = $null
$Interrupted = $null
$FieldsFound = @()
$FieldsMissing = @()

if ($null -ne $ToolResponse) {
    if ($null -ne $ToolResponse.stdout) {
        $Stdout = [string]$ToolResponse.stdout
        $FieldsFound += 'stdout'
    } else { $FieldsMissing += 'stdout' }

    if ($null -ne $ToolResponse.stderr) {
        $Stderr = [string]$ToolResponse.stderr
        $FieldsFound += 'stderr'
    } else { $FieldsMissing += 'stderr' }

    if ($null -ne $ToolResponse.exitCode) {
        $NativeExitCode = $ToolResponse.exitCode
        $FieldsFound += 'exitCode'
    } elseif ($null -ne $ToolResponse.exit_code) {
        $NativeExitCode = $ToolResponse.exit_code
        $FieldsFound += 'exit_code'
    } else { $FieldsMissing += 'exitCode' }

    if ($null -ne $ToolResponse.interrupted) {
        $Interrupted = $ToolResponse.interrupted
        $FieldsFound += 'interrupted'
    } else { $FieldsMissing += 'interrupted' }
} else {
    $FieldsMissing += 'tool_response'
}

# Exit code: native first, then parse EXIT=<N> marker from output
$ParsedExitCode = Parse-ExitMarker $Stdout $Stderr
$ExitCode = $NativeExitCode
$ExitCodeSource = 'native'
if ($null -eq $ExitCode -and $null -ne $ParsedExitCode) {
    $ExitCode = $ParsedExitCode
    $ExitCodeSource = 'parsed_marker'
    $FieldsFound += 'exit_code_parsed'
} elseif ($null -eq $ExitCode) {
    $ExitCodeSource = 'unavailable'
}

$OutputPreview = $null
$OutputBytes = 0
if ($Stdout) {
    $OutputBytes = $Stdout.Length
    if ($Stdout.Length -gt 2000) {
        $OutputPreview = $Stdout.Substring(0, 2000) + '... [truncated]'
    } else {
        $OutputPreview = $Stdout
    }
}

$Success = ($HookEvent -eq 'PostToolUse')

# Find matching gate in inflight/ — prefer tool_use_id, fall back to hash
$InflightDir = Join-Path $GateRoot 'inflight'
$EvidenceDir = Join-Path $GateRoot 'evidence'
$MatchedGateFile = $null
$CorrelationId = $null
$GateFileName = $null

# Pass 1: match by tool_use_id in filename (gate_check prefixes with tool_use_id)
if ($ToolUseId) {
    foreach ($gf in (Get-ChildItem $InflightDir -Filter '*.gate.json' -ErrorAction SilentlyContinue)) {
        if ($gf.Name.StartsWith($ToolUseId)) {
            try {
                $g = Get-Content $gf.FullName -Raw | ConvertFrom-Json
                $MatchedGateFile = $gf
                $CorrelationId = $g.correlation_id
                $GateFileName = $gf.Name
                break
            } catch {}
        }
    }
}

# Pass 2: fall back to command hash if tool_use_id match failed
if ($null -eq $MatchedGateFile) {
    foreach ($gf in (Get-ChildItem $InflightDir -Filter '*.gate.json' -ErrorAction SilentlyContinue)) {
        try {
            $g = Get-Content $gf.FullName -Raw | ConvertFrom-Json
            if ($g.command_sha256 -eq $Hash) {
                $MatchedGateFile = $gf
                $CorrelationId = $g.correlation_id
                $GateFileName = $gf.Name
                break
            }
        } catch {}
    }
}

# Orphan handling
$IsOrphan = ($null -eq $MatchedGateFile)
if ($IsOrphan) {
    $Ts = $NowUtc.ToString('yyyyMMdd-HHmmss')
    $Hash12 = $Hash.Substring(0, 12)
    $CorrelationId = "orphan-$Ts-$Hash12"
    $GateFileName = 'none'
}

$FilePrefix = "$DatePrefix-$CorrelationId"

# Write .result.json
$Result = [ordered]@{
    correlation_id   = $CorrelationId
    tool_use_id      = $ToolUseId
    session_id       = $SessionId
    command          = $Command
    command_sha256   = $Hash
    gate_file        = $GateFileName
    hook_event       = $HookEvent
    executed_utc     = $NowUtc.ToString('o')
    duration_ms      = $DurationMs
    cwd              = $PayloadCwd
    exit_code        = $ExitCode
    exit_code_source = $ExitCodeSource
    interrupted      = $Interrupted
    output_preview   = $OutputPreview
    output_bytes     = $OutputBytes
    success          = $Success
    fields_found     = $FieldsFound
    fields_missing   = $FieldsMissing
}

$ResultJson = $Result | ConvertTo-Json -Depth 5
$ResultPath = Join-Path $EvidenceDir "$FilePrefix.result.json"
try { [System.IO.File]::WriteAllText($ResultPath, $ResultJson, [System.Text.Encoding]::UTF8) } catch {}

# Write .tool_response.json (full, capped at 1MB)
if ($null -ne $ToolResponse) {
    $TrJson = $ToolResponse | ConvertTo-Json -Depth 10
    if ($TrJson.Length -gt 1048576) {
        $TrJson = $TrJson.Substring(0, 1048576) + "`n[TRUNCATED at 1MB]"
    }
    $TrPath = Join-Path $EvidenceDir "$FilePrefix.tool_response.json"
    try { [System.IO.File]::WriteAllText($TrPath, $TrJson, [System.Text.Encoding]::UTF8) } catch {}
}

# Write .stdout.txt
if ($Stdout) {
    $StdoutPath = Join-Path $EvidenceDir "$FilePrefix.stdout.txt"
    try { [System.IO.File]::WriteAllText($StdoutPath, $Stdout, [System.Text.Encoding]::UTF8) } catch {}
}

# Write .stderr.txt
if ($Stderr -and $Stderr.Length -gt 0) {
    $StderrPath = Join-Path $EvidenceDir "$FilePrefix.stderr.txt"
    try { [System.IO.File]::WriteAllText($StderrPath, $Stderr, [System.Text.Encoding]::UTF8) } catch {}
}

# Move gate from inflight to evidence
if (-not $IsOrphan -and $MatchedGateFile) {
    $GateDest = Join-Path $EvidenceDir "$FilePrefix.gate.json"
    try { Move-Item -Path $MatchedGateFile.FullName -Destination $GateDest -Force } catch {}
}

# Output additionalContext
$StatusWord = if ($Success) { 'succeeded' } else { 'failed' }
$ExitInfo = ''
if ($null -ne $ExitCode) {
    $ExitInfo = " Exit=$ExitCode (source: $ExitCodeSource)."
}
$Out = @{
    hookSpecificOutput = @{
        hookEventName = $HookEvent
        additionalContext = "[EVIDENCE:$CorrelationId] Command $StatusWord.$ExitInfo Compare EXPECTED from the gate vs ACTUAL output before creating the next gate."
    }
}

Write-Output ($Out | ConvertTo-Json -Depth 5 -Compress)
exit 0
