[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
# Reuse the frozen validator and semantic functions without changing contracts.
. (Join-Path $PSScriptRoot '../../contracts/tests/test_contract.ps1')
$taskGoldenRoot = Join-Path $PSScriptRoot 'fixtures/export/netflow_v9_canonical/golden'
$taskRecordsPassed = 0
$taskFilesPassed = 0
foreach ($taskGolden in Get-ChildItem -LiteralPath $taskGoldenRoot -Filter '*.jsonl' | Sort-Object Name) {
    $taskExpectedSha = (Get-Content -Raw -LiteralPath ([IO.Path]::ChangeExtension($taskGolden.FullName, '.sha256'))).Trim()
    $taskActualSha = (Get-FileHash -LiteralPath $taskGolden.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($taskActualSha -ne $taskExpectedSha) { throw "Golden SHA mismatch: $($taskGolden.Name)" }
    foreach ($taskLine in Get-Content -LiteralPath $taskGolden.FullName) {
        if (-not $taskLine) { throw "Unexpected blank canonical line: $($taskGolden.Name)" }
        $taskSchema = Invoke-SchemaValidation -Json $taskLine
        if (-not $taskSchema.IsValid) { throw "F7 schema failure: $($taskGolden.Name) $($taskSchema.Detail)" }
        $taskParsed = $taskLine | ConvertFrom-Json -Depth 100 -DateKind String
        $taskSemantics = Test-CanonicalSemantics -Observation $taskParsed
        if (-not $taskSemantics.IsValid) { throw "F7 semantic failure: $($taskGolden.Name) $($taskSemantics.Detail)" }
        $taskRecordsPassed += 1
    }
    $taskFilesPassed += 1
}
if ($taskFilesPassed -eq 0 -or $taskRecordsPassed -eq 0) { throw 'F7 golden validation requires positive evidence' }
Write-Host "F7 GOLDEN SCHEMA+SEMANTICS PASS=$taskRecordsPassed FAIL=0 HASH_FILES=$taskFilesPassed"
