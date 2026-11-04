#requires -Module Pester

# Runs the real hooks from a throwaway copy of .command-gate. Both hooks find their
# folders from their own location, so nothing here touches a live gate root.

BeforeAll {
    $script:SourceGate = Split-Path $PSScriptRoot -Parent
    $script:Day = (Get-Date).ToUniversalTime().ToString('yyyyMMdd')

    function New-TestGateRoot {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) "helios-evidence-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
        foreach ($dir in @('pending', 'inflight', 'evidence', 'blocked', 'session', 'templates', 'manifest')) {
            New-Item -ItemType Directory -Path (Join-Path $root $dir) -Force | Out-Null
        }
        foreach ($dir in @('hooks', 'policy', 'schema')) {
            Copy-Item -Path (Join-Path $script:SourceGate $dir) -Destination (Join-Path $root $dir) -Recurse -Force
        }
        return $root
    }

    function Get-TestSha256([string]$Text) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        return ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) -join ''
    }

    function New-InflightGate([string]$Root, [string]$Id, [string]$ToolUseId, [string]$Command = 'pwd') {
        $gate = [ordered]@{
            schema_version = 'command-gate.v1'
            correlation_id = $Id
            command        = $Command
            command_sha256 = Get-TestSha256 $Command
            risk_tier      = 0
        }
        $path = Join-Path $Root "inflight\$ToolUseId-test.gate.json"
        [System.IO.File]::WriteAllText($path, ($gate | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))
    }

    function Get-PostPayload([string]$ToolUseId, [string]$Command = 'pwd', $DurationMs = $null, [string]$Stdout = 'out', [string]$Stderr = '') {
        $payload = @{
            tool_name       = 'Bash'
            tool_input      = @{ command = $Command }
            tool_use_id     = $ToolUseId
            hook_event_name = 'PostToolUse'
            session_id      = 'test-session'
            cwd             = 'C:\work'
            tool_response   = @{ stdout = $Stdout; stderr = $Stderr; exitCode = 0; interrupted = $false }
        }
        if ($null -ne $DurationMs) { $payload['duration_ms'] = $DurationMs }
        return ($payload | ConvertTo-Json -Depth 5 -Compress)
    }

    function Invoke-PostHook([string]$Root, [string]$Payload) {
        return ($Payload | powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'hooks\evidence_capture.ps1') | Out-String)
    }

    function Get-Evidence([string]$Root, [string]$Name) {
        return (Join-Path $Root "evidence\$Name")
    }

    function Read-Result([string]$Root, [string]$Prefix) {
        return (Get-Content -LiteralPath (Get-Evidence $Root "$Prefix.result.json") -Raw | ConvertFrom-Json)
    }

    function Get-FamilyHashes([string]$Root, [string]$Prefix) {
        $hashes = @{}
        foreach ($file in (Get-ChildItem -LiteralPath (Join-Path $Root 'evidence') -File | Where-Object { $_.Name.StartsWith("$Prefix.") })) {
            $hashes[$file.Name] = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash
        }
        return $hashes
    }

    function New-Decision([string]$Root, [string]$SessionId, [string]$ToolUseId, [string]$Verdict, [string]$Stamp) {
        $dir = Join-Path $Root "evidence\integrity\sessions\$SessionId\commands"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        @{ timestamp_utc = $Stamp; verdict = $Verdict; session_id = $SessionId; tool_use_id = $ToolUseId } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $dir "$ToolUseId.decision.json") -Encoding UTF8
    }

    function New-PendingGate([string]$Root, [string]$Id, [string]$FileName, [string]$Command = 'pwd') {
        $now = (Get-Date).ToUniversalTime()
        $gate = [ordered]@{
            schema_version      = 'command-gate.v1'
            correlation_id      = $Id
            created_utc         = $now.ToString('o')
            expires_utc         = $now.AddHours(1).ToString('o')
            command             = $Command
            command_sha256      = Get-TestSha256 $Command
            working_directory   = 'C:\work'
            shell               = 'bash'
            risk_tier           = 0
            exit_capture        = 'not_applicable'
            exit_capture_reason = 'pure_output'
            multi_command       = $false
            segments            = @($Command)
            need                = 'Test need'
            expected            = 'Test expectation'
            actual_means        = 'Test meaning'
            next_logic          = 'Test next step'
            approval_boundary   = 'Test boundary'
        }
        $path = Join-Path $Root "pending\$FileName.gate.json"
        $gate | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding UTF8
        return $path
    }

    function Invoke-PreHook([string]$Root, [string]$ToolUseId, [string]$Command = 'pwd') {
        $payload = @{ tool_name = 'Bash'; tool_input = @{ command = $Command }; cwd = 'C:\work'; tool_use_id = $ToolUseId } | ConvertTo-Json -Compress
        $text = ($payload | powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'hooks\gate_check.ps1') | Out-String).Trim()
        if ($text -eq '{}') { return @{ Denied = $false; Reason = '' } }
        $json = $text | ConvertFrom-Json
        return @{ Denied = ($json.hookSpecificOutput.permissionDecision -eq 'deny'); Reason = $json.hookSpecificOutput.permissionDecisionReason }
    }
}

Describe 'evidence_capture file names' {

    BeforeEach { $script:Root = New-TestGateRoot }
    AfterEach { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue }

    It 'keeps the plain name on the first use of an id' {
        New-InflightGate $script:Root 'job-001' 'call-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a' -Stdout 'first') | Out-Null

        $plain = "$script:Day-job-001"
        foreach ($suffix in @('result.json', 'gate.json', 'tool_response.json', 'stdout.txt')) {
            Test-Path -LiteralPath (Get-Evidence $script:Root "$plain.$suffix") | Should -BeTrue
        }
        (Read-Result $script:Root $plain).correlation_id | Should -Be 'job-001'
        @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'inflight') -File).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'evidence') -File | Where-Object { $_.Name -like '*--*' }).Count | Should -Be 0
    }

    It 'writes a UTF-8 BOM, as the previous writer did' {
        New-InflightGate $script:Root 'job-002' 'call-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a') | Out-Null
        $bytes = [System.IO.File]::ReadAllBytes((Get-Evidence $script:Root "$script:Day-job-002.result.json"))
        ($bytes[0..2] | ForEach-Object { $_.ToString('x2') }) -join '' | Should -Be 'efbbbf'
    }

    It 'keeps both runs when an id is reused the same day' {
        $plain = "$script:Day-job-003"
        New-InflightGate $script:Root 'job-003' 'call-a' 'first command'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a' 'first command' -Stdout 'first' -Stderr 'first-err') | Out-Null
        $before = Get-FamilyHashes $script:Root $plain

        New-InflightGate $script:Root 'job-003' 'call-b' 'second command'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-b' 'second command' -Stdout 'second') | Out-Null

        $after = Get-FamilyHashes $script:Root $plain
        $after.Count | Should -Be $before.Count
        foreach ($name in $before.Keys) { $after[$name] | Should -Be $before[$name] }

        $second = "$plain--call-b"
        (Read-Result $script:Root $second).correlation_id | Should -Be 'job-003'
        (Read-Result $script:Root $second).command | Should -Be 'second command'
        (Read-Result $script:Root $plain).command | Should -Be 'first command'
        Test-Path -LiteralPath (Get-Evidence $script:Root "$second.gate.json") | Should -BeTrue
        Get-Content -LiteralPath (Get-Evidence $script:Root "$second.stdout.txt") -Raw | Should -Be 'second'
    }

    It 'never leaves a second result beside the first stderr' {
        $plain = "$script:Day-job-004"
        New-InflightGate $script:Root 'job-004' 'call-a' 'first command'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a' 'first command' -Stderr 'first-err') | Out-Null
        New-InflightGate $script:Root 'job-004' 'call-b' 'second command'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-b' 'second command') | Out-Null

        Test-Path -LiteralPath (Get-Evidence $script:Root "$plain.stderr.txt") | Should -BeTrue
        Test-Path -LiteralPath (Get-Evidence $script:Root "$plain--call-b.stderr.txt") | Should -BeFalse
    }

    It 'replaces nothing when one tool call is delivered three times' {
        $plain = "$script:Day-job-005"
        $call = "$plain--call-a"
        New-InflightGate $script:Root 'job-005' 'call-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a' -Stdout 'one') | Out-Null
        New-InflightGate $script:Root 'job-005' 'call-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a' -Stdout 'two') | Out-Null
        $plainHashes = Get-FamilyHashes $script:Root $plain
        $callHashes = Get-FamilyHashes $script:Root $call

        New-InflightGate $script:Root 'job-005' 'call-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a' -Stdout 'three') | Out-Null

        $afterPlain = Get-FamilyHashes $script:Root $plain
        $afterCall = Get-FamilyHashes $script:Root $call
        foreach ($name in $plainHashes.Keys) { $afterPlain[$name] | Should -Be $plainHashes[$name] }
        foreach ($name in $callHashes.Keys) { $afterCall[$name] | Should -Be $callHashes[$name] }
        Get-Content -LiteralPath (Get-Evidence $script:Root "$plain.stdout.txt") -Raw | Should -Be 'one'
        Get-Content -LiteralPath (Get-Evidence $script:Root "$call.stdout.txt") -Raw | Should -Be 'two'

        # The refused gate stays in inflight, and the failure is on record.
        @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'inflight') -File).Count | Should -Be 1
        $errors = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'posttooluse-errors') -Filter '*.error.json')
        $errors.Count | Should -BeGreaterThan 0
    }

    It 'names the files in the ledger entry' {
        New-InflightGate $script:Root 'job-006' 'call-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a') | Out-Null
        New-InflightGate $script:Root 'job-006' 'call-b'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-b') | Out-Null

        $ledger = Join-Path $script:Root 'session\session-ledger-test-session.jsonl'
        $entries = @(Get-Content -LiteralPath $ledger | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.event_type -eq 'posttooluse_evidence_written' })
        $entries.Count | Should -Be 2
        $entries[0].evidence_prefix | Should -Be "$script:Day-job-006"
        $entries[1].evidence_prefix | Should -Be "$script:Day-job-006--call-b"
        $entries[1].correlation_id | Should -Be 'job-006'
    }

    It 'tells the agent when a run gets the longer name' {
        New-InflightGate $script:Root 'job-007' 'call-a'
        $first = Invoke-PostHook $script:Root (Get-PostPayload 'call-a')
        New-InflightGate $script:Root 'job-007' 'call-b'
        $second = Invoke-PostHook $script:Root (Get-PostPayload 'call-b')

        $first | Should -Not -Match 'EVIDENCE NAME'
        $second | Should -Match 'EVIDENCE NAME'
    }

    It 'keeps the result inside evidence for the unusable id <id>' -TestCases @(
        @{ id = 'a:b' }
        @{ id = 'a*b' }
        @{ id = 'a/b' }
        @{ id = 'a b' }
        @{ id = '..\..\..\escaped' }
    ) {
        New-InflightGate $script:Root $id 'call-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a') | Out-Null

        $safe = $id -replace '[^A-Za-z0-9._-]', '_'
        $prefix = "$script:Day-$safe--call-a"
        (Read-Result $script:Root $prefix).correlation_id | Should -Be $id
    }

    It 'writes nothing outside evidence for a path traversal id' {
        $id = '..\..\..\escaped'
        New-InflightGate $script:Root $id 'call-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a') | Out-Null

        $evidenceDir = Join-Path $script:Root 'evidence'
        $target = [System.IO.Path]::GetFullPath((Join-Path $script:Root "evidence\$script:Day-$id.result.json"))
        $target.StartsWith($evidenceDir) | Should -BeFalse
        [System.IO.File]::Exists($target) | Should -BeFalse
        @(Get-ChildItem -LiteralPath $script:Root -Recurse -File -Filter '*escaped*' | Where-Object { $_.DirectoryName -ne $evidenceDir }).Count | Should -Be 0
    }

    It 'keeps the result for an id too long for a path' {
        $id = 'x' * 300
        New-InflightGate $script:Root $id 'call-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a') | Out-Null

        $results = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'evidence') -File -Filter '*.result.json')
        $results.Count | Should -Be 1
        $results[0].Name | Should -Match '--call-a\.result\.json$'
        $results[0].Name.Length | Should -BeLessThan 150
        (Get-Content -LiteralPath $results[0].FullName -Raw | ConvertFrom-Json).correlation_id | Should -Be $id
    }

    It 'still records a command that had no gate' {
        Invoke-PostHook $script:Root (Get-PostPayload 'call-a') | Out-Null
        $results = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'evidence') -File -Filter '*.result.json')
        $results.Count | Should -Be 1
        $results[0].Name | Should -Match "^$script:Day-orphan-"
    }

    It 'keeps every result when calls race for one id' {
        $hook = Join-Path $script:Root 'hooks\evidence_capture.ps1'
        $processes = foreach ($n in 1..6) {
            New-InflightGate $script:Root 'job-race' "call-$n"
            $payloadFile = Join-Path $script:Root "payload-$n.json"
            [System.IO.File]::WriteAllText($payloadFile, (Get-PostPayload "call-$n"), [System.Text.UTF8Encoding]::new($false))
            Start-Process powershell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$hook`"") `
                -RedirectStandardInput $payloadFile `
                -RedirectStandardOutput (Join-Path $script:Root "out-$n.txt") `
                -RedirectStandardError (Join-Path $script:Root "err-$n.txt") `
                -NoNewWindow -PassThru
        }
        $processes | Wait-Process -Timeout 180

        $results = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'evidence') -File -Filter "$script:Day-job-race*.result.json")
        $results.Count | Should -Be 6
        @($results | Where-Object { $_.Name -eq "$script:Day-job-race.result.json" }).Count | Should -Be 1
        $tools = $results | ForEach-Object { (Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json).tool_use_id } | Sort-Object -Unique
        @($tools).Count | Should -Be 6
        @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'inflight') -File).Count | Should -Be 0
    }
}

Describe 'evidence_capture start time' {

    BeforeEach { $script:Root = New-TestGateRoot }
    AfterEach { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue }

    It 'records the admission stamp when the host reports no duration' {
        $stamp = '2026-11-04T10:00:00.1234567Z'
        New-InflightGate $script:Root 'job-101' 'exec-a'
        New-Decision $script:Root 'test-session' 'exec-a' 'ALLOW' $stamp
        Invoke-PostHook $script:Root (Get-PostPayload 'exec-a') | Out-Null

        $result = Read-Result $script:Root "$script:Day-job-101"
        $result.started_utc | Should -Be $stamp
        $result.started_utc_source | Should -Be 'pretooluse_decision'
        $result.duration_ms | Should -BeNullOrEmpty
    }

    It 'adds no start when the host reports a duration' {
        New-InflightGate $script:Root 'job-102' 'toolu-a'
        New-Decision $script:Root 'test-session' 'toolu-a' 'ALLOW' '2026-11-04T10:00:00.1234567Z'
        Invoke-PostHook $script:Root (Get-PostPayload 'toolu-a' -DurationMs 42) | Out-Null

        $result = Read-Result $script:Root "$script:Day-job-102"
        $result.duration_ms | Should -Be 42
        @($result.PSObject.Properties.Name) | Should -Not -Contain 'started_utc'
    }

    It 'adds no start from a decision that was not an ALLOW' {
        New-InflightGate $script:Root 'job-103' 'exec-a'
        New-Decision $script:Root 'test-session' 'exec-a' 'DENY' '2026-11-04T10:00:00.1234567Z'
        Invoke-PostHook $script:Root (Get-PostPayload 'exec-a') | Out-Null

        @((Read-Result $script:Root "$script:Day-job-103").PSObject.Properties.Name) | Should -Not -Contain 'started_utc'
    }

    It 'adds no start when no decision exists' {
        New-InflightGate $script:Root 'job-104' 'exec-a'
        Invoke-PostHook $script:Root (Get-PostPayload 'exec-a') | Out-Null

        @((Read-Result $script:Root "$script:Day-job-104").PSObject.Properties.Name) | Should -Not -Contain 'started_utc'
    }
}

Describe 'gate_check correlation ids' {

    BeforeEach { $script:Root = New-TestGateRoot }
    AfterEach { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue }

    It 'admits a new id' {
        $gatePath = New-PendingGate $script:Root 'job-201' 'job-201'
        $outcome = Invoke-PreHook $script:Root 'call-a'

        $outcome.Denied | Should -BeFalse
        Test-Path -LiteralPath $gatePath | Should -BeFalse
        @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'inflight') -File).Count | Should -Be 1
    }

    It 'refuses an id with evidence from <label>' -TestCases @(
        @{ label = 'today'; file = "$((Get-Date).ToUniversalTime().ToString('yyyyMMdd'))-job-202.result.json" }
        @{ label = 'an earlier day'; file = '20250101-job-202.result.json' }
    ) {
        Set-Content -LiteralPath (Get-Evidence $script:Root $file) -Value '{}'
        $gatePath = New-PendingGate $script:Root 'job-202' 'job-202'
        $outcome = Invoke-PreHook $script:Root 'call-a'

        $outcome.Denied | Should -BeTrue
        $outcome.Reason | Should -Match 'correlation_id already used'
        Test-Path -LiteralPath $gatePath | Should -BeTrue
        @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'inflight') -File).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'blocked') -File).Count | Should -BeGreaterThan 0
    }

    It 'admits an id that only ends the same way as a used one' {
        Set-Content -LiteralPath (Get-Evidence $script:Root "$script:Day-task-job-203.result.json") -Value '{}'
        New-PendingGate $script:Root 'job-203' 'job-203' | Out-Null
        (Invoke-PreHook $script:Root 'call-a').Denied | Should -BeFalse
    }

    It 'refuses the unusable id <id>' -TestCases @(
        @{ id = 'a:b' }
        @{ id = 'a*b' }
        @{ id = 'a/b' }
        @{ id = 'a b' }
        @{ id = '..\escaped' }
    ) {
        New-PendingGate $script:Root $id 'odd-id' | Out-Null
        $outcome = Invoke-PreHook $script:Root 'call-a'

        $outcome.Denied | Should -BeTrue
        $outcome.Reason | Should -Match 'not usable in a file name'
    }

    It 'refuses an id over 120 characters' {
        New-PendingGate $script:Root ('x' * 121) 'long-id' | Out-Null
        $outcome = Invoke-PreHook $script:Root 'call-a'

        $outcome.Denied | Should -BeTrue
        $outcome.Reason | Should -Match 'not usable in a file name'
    }

    It 'shows at most 130 characters of a very long id in the refusal' {
        New-PendingGate $script:Root ('x' * 5000) 'long-id' | Out-Null
        $outcome = Invoke-PreHook $script:Root 'call-a'

        $outcome.Denied | Should -BeTrue
        $outcome.Reason | Should -Not -Match ('x' * 131)
    }

    It 'takes a gate with a new id when a stale gate has a used one' {
        Set-Content -LiteralPath (Get-Evidence $script:Root '20250101-job-204.result.json') -Value '{}'
        New-PendingGate $script:Root 'job-204' 'a-stale' | Out-Null
        New-PendingGate $script:Root 'job-205' 'b-fresh' | Out-Null
        $outcome = Invoke-PreHook $script:Root 'call-a'

        $outcome.Denied | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:Root 'pending\a-stale.gate.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Root 'inflight\call-a-b-fresh.gate.json') | Should -BeTrue
    }
}
