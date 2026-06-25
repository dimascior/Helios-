$ErrorActionPreference = 'SilentlyContinue'

$GateRoot = Join-Path $PSScriptRoot '.command-gate'
$HookScript = Join-Path $GateRoot 'hooks\gate_check.ps1'

function Get-Sha256([string]$Text) {
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    $Hash = $Sha.ComputeHash($Bytes)
    return ($Hash | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Show-Banner([string]$Text, [ConsoleColor]$Color = 'Cyan') {
    Write-Host ""
    Write-Host ([string]::new([char]0x2501, 64)) -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host ([string]::new([char]0x2501, 64)) -ForegroundColor $Color
    Write-Host ""
}

function Invoke-GateHook([string]$Command) {
    $payload = @{
        tool_name  = 'Bash'
        tool_input = @{ command = $Command }
        cwd        = $PSScriptRoot
        tool_use_id = "demo-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    } | ConvertTo-Json -Compress

    $raw = $payload | powershell -NoProfile -ExecutionPolicy Bypass -File $HookScript 2>&1
    $text = ($raw | Out-String).Trim()

    if ([string]::IsNullOrEmpty($text) -or $text -eq '{}') {
        return @{ Allowed = $true; Reason = '' }
    }
    try {
        $json = $text | ConvertFrom-Json
        if ($json.hookSpecificOutput.permissionDecision -eq 'deny') {
            return @{ Allowed = $false; Reason = $json.hookSpecificOutput.permissionDecisionReason }
        }
        return @{ Allowed = $true; Reason = '' }
    } catch {
        return @{ Allowed = $false; Reason = $text }
    }
}

function Show-Result($r) {
    if ($r.Allowed) {
        Write-Host "  [PASS] Gate validated" -ForegroundColor Green
    } else {
        Write-Host "  [BLOCKED]" -ForegroundColor Red
        $r.Reason -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    }
    Write-Host ""
}

# ── START ──

Clear-Host
Show-Banner "HELIOS COMMAND-GATE SYSTEM" Yellow
Write-Host "  Every shell command passes through the gate before execution." -ForegroundColor Gray
Write-Host "  No gate file = no execution. No exceptions." -ForegroundColor Gray
Start-Sleep 3

# ── 1. Tier 4: unconditionally forbidden ──
Show-Banner "1. FORBIDDEN (Tier 4)"
Write-Host "  Command: " -NoNewline -ForegroundColor Gray
Write-Host "format C:" -ForegroundColor White
Write-Host ""
Start-Sleep 1
Show-Result (Invoke-GateHook "format C:")
Start-Sleep 4

# ── 2. No gate file ──
Show-Banner "2. NO GATE FILE"
Write-Host "  Command: " -NoNewline -ForegroundColor Gray
Write-Host "pwd" -ForegroundColor White
Write-Host ""
Start-Sleep 1
Show-Result (Invoke-GateHook "pwd")
Start-Sleep 4

# ── 3. Valid gate ──
Show-Banner "3. AUTHORIZED (valid gate)"
$cmd = "echo hello"
$hash = Get-Sha256 $cmd
$now = (Get-Date).ToUniversalTime()

Write-Host "  Creating single-use gate for: " -NoNewline -ForegroundColor Gray
Write-Host $cmd -ForegroundColor White
Write-Host "  SHA256: $hash" -ForegroundColor DarkGray
Write-Host ""

$gate = @{
    schema_version    = 'command-gate.v1'
    correlation_id    = 'demo-echo'
    created_utc       = $now.ToString('o')
    expires_utc       = $now.AddHours(1).ToString('o')
    command           = $cmd
    command_sha256    = $hash
    working_directory = $PSScriptRoot
    shell             = 'bash'
    risk_tier         = 0
    exit_capture      = 'not_applicable'
    exit_capture_reason = 'pure_output'
    multi_command     = $false
    segments          = @()
    need              = 'Demo: verify gate lifecycle'
    expected          = 'Prints hello'
    actual_means      = 'Gate validates and moves to inflight'
    next_logic        = 'Evidence capture archives the result'
    approval_boundary = 'This gate makes the command eligible for permission flow only; it does not auto-approve execution.'
}

$gatePath = Join-Path $GateRoot 'pending\demo-echo.gate.json'
$gate | ConvertTo-Json -Depth 4 | Set-Content -Path $gatePath -Encoding UTF8
Write-Host "  Gate written to pending/" -ForegroundColor Cyan
Start-Sleep 2

Write-Host ""
Write-Host "  Executing through hook..." -ForegroundColor Gray
Start-Sleep 1
Show-Result (Invoke-GateHook $cmd)

$moved = Get-ChildItem (Join-Path $GateRoot 'inflight') -Filter '*demo-echo.gate.json' -ErrorAction SilentlyContinue
if ($moved) {
    Write-Host "  Lifecycle: pending/ -> inflight/" -ForegroundColor Green
    Write-Host "    $($moved[0].Name)" -ForegroundColor DarkGreen
    Remove-Item $moved[0].FullName -Force -ErrorAction SilentlyContinue
}
Start-Sleep 3

# ── Summary ──
Show-Banner "GATE LIFECYCLE" Magenta
Write-Host "  pending/    Gate created with hash, tier, justification" -ForegroundColor Gray
Write-Host "      |" -ForegroundColor DarkGray
Write-Host "  inflight/   Hook validates, moves gate here during execution" -ForegroundColor Gray
Write-Host "      |" -ForegroundColor DarkGray
Write-Host "  evidence/   After execution: gate + stdout + result archived" -ForegroundColor Gray
Write-Host ""
Write-Host "  Single-use. Auditable. No command runs without a gate." -ForegroundColor Yellow
Write-Host ""
