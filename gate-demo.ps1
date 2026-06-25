$ErrorActionPreference = 'SilentlyContinue'

$GateRoot  = Join-Path $PSScriptRoot '.command-gate'
$PreHook   = Join-Path $GateRoot 'hooks\gate_check.ps1'
$PostHook  = Join-Path $GateRoot 'hooks\evidence_capture.ps1'
$DemoDir   = $PSScriptRoot

function Get-Sha256([string]$Text) {
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $Sha   = [System.Security.Cryptography.SHA256]::Create()
    $Hash  = $Sha.ComputeHash($Bytes)
    return ($Hash | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Bar([ConsoleColor]$c) { Write-Host ([string]::new([char]0x2501, 72)) -ForegroundColor $c }

function Show-Banner([string]$Text, [ConsoleColor]$Color = 'Cyan') {
    Write-Host ''; Bar $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Bar $Color; Write-Host ''
}

function Label([string]$l, [string]$v, [ConsoleColor]$lc = 'DarkCyan', [ConsoleColor]$vc = 'White') {
    Write-Host "    $l " -NoNewline -ForegroundColor $lc; Write-Host $v -ForegroundColor $vc
}

# ── Hook invocation ──

function Invoke-Pre([string]$Command, [string]$ToolUseId, [string]$ToolName = 'Bash') {
    $p = @{ tool_name = $ToolName; tool_input = @{ command = $Command }; cwd = $DemoDir; tool_use_id = $ToolUseId } | ConvertTo-Json -Compress
    $raw = $p | powershell -NoProfile -ExecutionPolicy Bypass -File $PreHook 2>&1
    $text = ($raw | Out-String).Trim()
    if ([string]::IsNullOrEmpty($text) -or $text -eq '{}') { return @{ Ok = $true; Msg = '' } }
    try {
        $j = $text | ConvertFrom-Json
        if ($j.hookSpecificOutput.permissionDecision -eq 'deny') { return @{ Ok = $false; Msg = $j.hookSpecificOutput.permissionDecisionReason } }
        return @{ Ok = $true; Msg = '' }
    } catch { return @{ Ok = $false; Msg = $text } }
}

function Invoke-Post([string]$Command, [string]$ToolUseId, [string]$Stdout, [int]$ExitCode = 0, [string]$ToolName = 'Bash') {
    $p = @{
        tool_name       = $ToolName
        tool_input      = @{ command = $Command }
        tool_use_id     = $ToolUseId
        hook_event_name = 'PostToolUse'
        session_id      = 'demo-session'
        cwd             = $DemoDir
        duration_ms     = 42
        tool_response   = @{ stdout = $Stdout; stderr = ''; exitCode = $ExitCode; interrupted = $false }
    } | ConvertTo-Json -Depth 4 -Compress
    $p | powershell -NoProfile -ExecutionPolicy Bypass -File $PostHook 2>&1 | Out-Null
}

# ── Gate builder ──

function New-Gate {
    param([string]$Id, [string]$Cmd, [int]$Tier, [string]$Shell = 'bash', [hashtable]$Fields)
    $hash = Get-Sha256 $Cmd
    $now  = (Get-Date).ToUniversalTime()
    $g = [ordered]@{
        schema_version    = 'command-gate.v1'
        correlation_id    = $Id
        created_utc       = $now.ToString('o')
        expires_utc       = $now.AddHours(1).ToString('o')
        command           = $Cmd
        command_sha256    = $hash
        working_directory = $DemoDir
        shell             = $Shell
        risk_tier         = $Tier
        exit_capture      = 'not_applicable'
        exit_capture_reason = 'pure_output'
        multi_command     = $false
        segments          = @()
    }
    foreach ($k in $Fields.Keys) { $g[$k] = $Fields[$k] }
    $g['approval_boundary'] = 'This gate makes the command eligible for permission flow only; it does not auto-approve execution.'
    $path = Join-Path $GateRoot "pending\$Id.gate.json"
    $g | ConvertTo-Json -Depth 4 | Set-Content -Path $path -Encoding UTF8
    return @{ Path = $path; Hash = $hash; Gate = $g }
}

# ── Evidence display ──

function Show-Evidence([string]$Id) {
    $date    = (Get-Date).ToUniversalTime().ToString('yyyyMMdd')
    $prefix  = "$date-$Id"
    $evDir   = Join-Path $GateRoot 'evidence'
    $files   = Get-ChildItem $evDir -Filter "$prefix.*" -ErrorAction SilentlyContinue | Sort-Object Name
    if ($files.Count -eq 0) { Write-Host "    (no evidence files found)" -ForegroundColor DarkGray; return }

    Write-Host "    Evidence package:" -ForegroundColor Cyan
    foreach ($f in $files) {
        $ext = $f.Extension
        $icon = switch ($ext) {
            '.json' { '[JSON]' }
            '.txt'  { '[TEXT]' }
            default { '[FILE]' }
        }
        Write-Host "      $icon $($f.Name)" -ForegroundColor DarkCyan
    }
    Write-Host ''

    # Show result.json key fields
    $resultFile = $files | Where-Object { $_.Name -like '*.result.json' } | Select-Object -First 1
    if ($resultFile) {
        Write-Host "    result.json:" -ForegroundColor Cyan
        try {
            $r = Get-Content $resultFile.FullName -Raw | ConvertFrom-Json
            Label 'correlation_id:' $r.correlation_id
            Label 'command_sha256:' $r.command_sha256
            Label 'exit_code:'      "$($r.exit_code) (source: $($r.exit_code_source))"
            Label 'success:'        "$($r.success)"
            Label 'output_preview:' $(if ($r.output_preview.Length -gt 60) { $r.output_preview.Substring(0,60) + '...' } else { $r.output_preview })
        } catch {}
        Write-Host ''
    }

    # Show gate.json tier + key fields
    $gateFile = $files | Where-Object { $_.Name -like '*.gate.json' } | Select-Object -First 1
    if ($gateFile) {
        Write-Host "    gate.json (archived):" -ForegroundColor Cyan
        try {
            $g = Get-Content $gateFile.FullName -Raw | ConvertFrom-Json
            Label 'risk_tier:'  "$($g.risk_tier)"
            Label 'need:'       $g.need
            Label 'expected:'   $g.expected
            if ($g.stop_conditions)   { Label 'stop_conditions:'   $g.stop_conditions }
            if ($g.read_write_impact) { Label 'read_write_impact:' ($g.read_write_impact | ConvertTo-Json -Compress) }
        } catch {}
        Write-Host ''
    }
}

function Show-Blocked([string]$Hash) {
    $blkDir = Join-Path $GateRoot 'blocked'
    $hash12 = $Hash.Substring(0, 12)
    $files  = Get-ChildItem $blkDir -Filter "*$hash12*" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($files) {
        Write-Host "    Blocked record:" -ForegroundColor Red
        Write-Host "      $($files.Name)" -ForegroundColor DarkRed
        try {
            $b = Get-Content $files.FullName -Raw | ConvertFrom-Json
            Label 'tier:'   "$($b.tier)" DarkRed White
            Label 'reason:' $(if ($b.reason.Length -gt 80) { $b.reason.Substring(0,80) + '...' } else { $b.reason }) DarkRed Yellow
        } catch {}
        Write-Host ''
    }
}

# ── Cleanup helper ──
function Cleanup-Demo {
    $date  = (Get-Date).ToUniversalTime().ToString('yyyyMMdd')
    $evDir = Join-Path $GateRoot 'evidence'
    $ifDir = Join-Path $GateRoot 'inflight'
    Get-ChildItem $evDir   -Filter "$date-demo-t*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem $ifDir   -Filter '*demo-t*'      -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem (Join-Path $GateRoot 'pending') -Filter 'demo-t*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

# ═══════════════════════════════════════════════════════════════
#  DEMO START
# ═══════════════════════════════════════════════════════════════

Cleanup-Demo
Clear-Host

Show-Banner 'HELIOS COMMAND-GATE SYSTEM' Yellow
Write-Host '  Every shell command an AI agent executes must pass through a' -ForegroundColor Gray
Write-Host '  single-use gate file. This demo invokes the real PreToolUse and' -ForegroundColor Gray
Write-Host '  PostToolUse hooks to trace each tier through the full lifecycle.' -ForegroundColor Gray
Write-Host ''
Write-Host '  pending/ -> inflight/ -> evidence/    (or blocked/)' -ForegroundColor DarkGray
Start-Sleep 3

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TIER 4: FORBIDDEN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clear-Host
Show-Banner 'TIER 4: FORBIDDEN — format C:' Red

$t4cmd  = 'format C:'
$t4hash = Get-Sha256 $t4cmd

Write-Host '  Tier 4 commands are unconditionally blocked.' -ForegroundColor Gray
Write-Host '  No gate file can authorize them.' -ForegroundColor Gray
Write-Host ''
Label 'command:'       $t4cmd Gray White
Label 'command_sha256:' $t4hash Gray DarkGray
Write-Host ''
Start-Sleep 1

Write-Host '  Invoking PreToolUse hook...' -ForegroundColor DarkGray
$r = Invoke-Pre $t4cmd 'demo-t4'
Write-Host ''
Write-Host '  [BLOCKED] ' -NoNewline -ForegroundColor Red
Write-Host 'TIER 4 FORBIDDEN' -ForegroundColor Yellow
$r.Msg -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
Write-Host ''

Show-Blocked $t4hash
Start-Sleep 4

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TIER 0: ROUTINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clear-Host
Show-Banner 'TIER 0: ROUTINE — pwd' Green

$t0cmd = 'pwd'

Write-Host '  Step 1: Attempt without gate' -ForegroundColor DarkYellow
Label 'command:' $t0cmd
Write-Host ''
$r = Invoke-Pre $t0cmd 'demo-t0-attempt'
Write-Host '  [BLOCKED] ' -NoNewline -ForegroundColor Red
$r.Msg -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
Write-Host ''
Start-Sleep 2

Write-Host '  Step 2: Create gate with Tier 0 required fields' -ForegroundColor DarkYellow
$g0 = New-Gate -Id 'demo-t0-routine' -Cmd $t0cmd -Tier 0 -Fields @{
    need         = 'Confirm working directory before file operations'
    expected     = 'Prints absolute path of current directory'
    actual_means = 'Agent knows its filesystem context'
    next_logic   = 'Proceed with file-relative commands using this path'
}
Label 'gate file:'     'pending/demo-t0-routine.gate.json'
Label 'command_sha256:' $g0.Hash
Label 'risk_tier:'      '0'
Label 'need:'           $g0.Gate.need
Label 'expected:'       $g0.Gate.expected
Write-Host ''
Start-Sleep 2

Write-Host '  Step 3: Execute through PreToolUse hook' -ForegroundColor DarkYellow
$r = Invoke-Pre $t0cmd 'demo-t0-routine' 'Bash'
if ($r.Ok) {
    Write-Host '  [PASS] ' -NoNewline -ForegroundColor Green
    Write-Host 'Gate validated — moved pending/ -> inflight/' -ForegroundColor Green
} else {
    Write-Host "  [FAIL] $($r.Msg)" -ForegroundColor Red
}
Write-Host ''
Start-Sleep 1

Write-Host '  Step 4: PostToolUse — capture evidence' -ForegroundColor DarkYellow
Invoke-Post -Command $t0cmd -ToolUseId 'demo-t0-routine' -Stdout '/c/Users/you/project'
Write-Host '  Evidence captured — inflight/ -> evidence/' -ForegroundColor Green
Write-Host ''
Start-Sleep 1

Show-Evidence 'demo-t0-routine'
Start-Sleep 4

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TIER 1: DIAGNOSTIC
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clear-Host
Show-Banner 'TIER 1: DIAGNOSTIC — Get-Process explorer' Cyan

$t1cmd = 'Get-Process -Name explorer'

Write-Host '  Step 1: Attempt without gate' -ForegroundColor DarkYellow
$r = Invoke-Pre $t1cmd 'demo-t1-attempt' 'PowerShell'
Write-Host '  [BLOCKED] ' -NoNewline -ForegroundColor Red
$r.Msg -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
Write-Host ''
Start-Sleep 2

Write-Host '  Step 2: Create gate' -ForegroundColor DarkYellow
$g1 = New-Gate -Id 'demo-t1-diag' -Cmd $t1cmd -Tier 1 -Shell 'powershell' -Fields @{
    need         = 'Check if explorer.exe is running before UI automation'
    expected     = 'Process listing with PID, CPU, memory for explorer'
    actual_means = 'Explorer is alive and responsive — safe to send window messages'
    next_logic   = 'Proceed with UI automation targeting explorer PID'
}
Label 'risk_tier:' '1'
Label 'need:'      $g1.Gate.need
Write-Host ''
Start-Sleep 1

Write-Host '  Step 3: PreToolUse' -ForegroundColor DarkYellow
$r = Invoke-Pre $t1cmd 'demo-t1-diag' 'PowerShell'
if ($r.Ok) { Write-Host '  [PASS] pending/ -> inflight/' -ForegroundColor Green }
Write-Host ''

Write-Host '  Step 4: PostToolUse' -ForegroundColor DarkYellow
$simOut = "Handles  NPM(K)  PM(K)  WS(K)  CPU(s)    Id  ProcessName`n   1842      89  98204 142568    12.50  4820  explorer"
Invoke-Post -Command $t1cmd -ToolUseId 'demo-t1-diag' -Stdout $simOut -ToolName 'PowerShell'
Write-Host '  Evidence captured — inflight/ -> evidence/' -ForegroundColor Green
Write-Host ''
Start-Sleep 1

Show-Evidence 'demo-t1-diag'
Start-Sleep 4

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TIER 2: REMOTE / ADMIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clear-Host
Show-Banner 'TIER 2: REMOTE ADMIN — curl localhost:8080/health' Yellow

$t2cmd = 'curl localhost:8080/health'

Write-Host '  Step 1: Attempt without gate' -ForegroundColor DarkYellow
$r = Invoke-Pre $t2cmd 'demo-t2-attempt'
Write-Host '  [BLOCKED] ' -NoNewline -ForegroundColor Red
$r.Msg -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
Write-Host ''
Start-Sleep 2

Write-Host '  Step 2: Create gate — Tier 2 requires stop_conditions' -ForegroundColor DarkYellow
$g2 = New-Gate -Id 'demo-t2-remote' -Cmd $t2cmd -Tier 2 -Fields @{
    need            = 'Verify local API server is healthy before running integration tests'
    expected        = 'JSON response with status: ok and uptime > 0'
    actual_means    = 'Server is ready to accept test traffic'
    next_logic      = 'Run integration test suite against localhost:8080'
    stop_conditions = 'Abort if status != ok, if connection refused, or if response time > 5s'
}
Label 'risk_tier:'       '2'
Label 'stop_conditions:' $g2.Gate.stop_conditions
Write-Host ''
Start-Sleep 1

Write-Host '  Step 3: PreToolUse' -ForegroundColor DarkYellow
$r = Invoke-Pre $t2cmd 'demo-t2-remote'
if ($r.Ok) { Write-Host '  [PASS] pending/ -> inflight/' -ForegroundColor Green }
Write-Host ''

Write-Host '  Step 4: PostToolUse' -ForegroundColor DarkYellow
Invoke-Post -Command $t2cmd -ToolUseId 'demo-t2-remote' -Stdout '{"status":"ok","uptime":3842,"version":"2.1.0"}'
Write-Host '  Evidence captured — inflight/ -> evidence/' -ForegroundColor Green
Write-Host ''
Start-Sleep 1

Show-Evidence 'demo-t2-remote'
Start-Sleep 4

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TIER 3: MODIFYING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clear-Host
Show-Banner 'TIER 3: MODIFYING — git push origin main' Magenta

$t3cmd = 'git push origin main'

Write-Host '  Step 1: Attempt without gate' -ForegroundColor DarkYellow
$r = Invoke-Pre $t3cmd 'demo-t3-attempt'
Write-Host '  [BLOCKED] ' -NoNewline -ForegroundColor Red
$r.Msg -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
Write-Host ''
Start-Sleep 2

Write-Host '  Step 2: Create gate — Tier 3 requires stop_conditions + read_write_impact' -ForegroundColor DarkYellow
$g3 = New-Gate -Id 'demo-t3-modify' -Cmd $t3cmd -Tier 3 -Fields @{
    need              = 'Push committed README update to remote'
    expected          = 'Push succeeds: local main -> origin/main fast-forward'
    actual_means      = 'Remote repository now has the latest documentation'
    next_logic        = 'Verify push on GitHub; update any dependent CI pipelines'
    stop_conditions   = 'Abort if push is rejected, if force-push is required, or if CI status is failing'
    read_write_impact = @{
        reads  = @('.git/refs/heads/main')
        writes = @('origin/main (remote)')
    }
}
Label 'risk_tier:'        '3'
Label 'stop_conditions:'  $g3.Gate.stop_conditions
Label 'read_write_impact:' ($g3.Gate.read_write_impact | ConvertTo-Json -Compress)
Write-Host ''
Start-Sleep 1

Write-Host '  Step 3: PreToolUse' -ForegroundColor DarkYellow
$r = Invoke-Pre $t3cmd 'demo-t3-modify'
if ($r.Ok) { Write-Host '  [PASS] pending/ -> inflight/' -ForegroundColor Green }
Write-Host ''

Write-Host '  Step 4: PostToolUse' -ForegroundColor DarkYellow
Invoke-Post -Command $t3cmd -ToolUseId 'demo-t3-modify' -Stdout 'To https://github.com/user/repo.git  abc1234..def5678  main -> main'
Write-Host '  Evidence captured — inflight/ -> evidence/' -ForegroundColor Green
Write-Host ''
Start-Sleep 1

Show-Evidence 'demo-t3-modify'
Start-Sleep 4

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SUMMARY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clear-Host
Show-Banner 'GATE LIFECYCLE SUMMARY' Yellow

Write-Host '  Tier  Outcome     Required Fields' -ForegroundColor White
Write-Host '  ----  ----------  ------------------------------------------------' -ForegroundColor DarkGray
Write-Host '   4    ' -NoNewline -ForegroundColor White; Write-Host 'FORBIDDEN   ' -NoNewline -ForegroundColor Red;    Write-Host 'Unconditionally blocked. No gate accepted.' -ForegroundColor Gray
Write-Host '   3    ' -NoNewline -ForegroundColor White; Write-Host 'GATED       ' -NoNewline -ForegroundColor Magenta; Write-Host 'need, expected, actual_means, next_logic,' -ForegroundColor Gray
Write-Host '                    ' -NoNewline; Write-Host 'stop_conditions, read_write_impact' -ForegroundColor Gray
Write-Host '   2    ' -NoNewline -ForegroundColor White; Write-Host 'GATED       ' -NoNewline -ForegroundColor Yellow;  Write-Host 'need, expected, actual_means, next_logic,' -ForegroundColor Gray
Write-Host '                    ' -NoNewline; Write-Host 'stop_conditions' -ForegroundColor Gray
Write-Host '   1    ' -NoNewline -ForegroundColor White; Write-Host 'GATED       ' -NoNewline -ForegroundColor Cyan;    Write-Host 'need, expected, actual_means, next_logic' -ForegroundColor Gray
Write-Host '   0    ' -NoNewline -ForegroundColor White; Write-Host 'GATED       ' -NoNewline -ForegroundColor Green;   Write-Host 'need, expected, actual_means, next_logic' -ForegroundColor Gray
Write-Host ''

Write-Host '  Evidence chain per command:' -ForegroundColor White
Write-Host '    .gate.json           Original gate (archived from inflight/)' -ForegroundColor DarkGray
Write-Host '    .result.json         Exit code, output preview, timing, success' -ForegroundColor DarkGray
Write-Host '    .tool_response.json  Full tool response from Claude Code' -ForegroundColor DarkGray
Write-Host '    .stdout.txt          Raw command output' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  Single-use. Auditable. No command runs without a gate.' -ForegroundColor Yellow
Write-Host ''
Start-Sleep 5

Cleanup-Demo
