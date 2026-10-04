[CmdletBinding()]
param([Parameter(Mandatory)] [string[]] $RunDirectories)
$ErrorActionPreference = 'Stop'
# Reuse BOTH frozen schema and its independent timestamp/order semantics.
. (Join-Path $PSScriptRoot '../../contracts/tests/test_contract.ps1')
$taskRecordsPassed = 0
foreach ($taskRunDirectory in $RunDirectories) {
    $taskCanonicalPath = Join-Path $taskRunDirectory 'canonical_observations.jsonl'
    if (-not (Test-Path -LiteralPath (Join-Path $taskRunDirectory 'run_complete.json'))) {
        throw 'E2E output is not complete'
    }
    $taskExpectedCount = (Get-Content -Raw -LiteralPath (Join-Path $taskRunDirectory 'ingestion_status.json') |
        ConvertFrom-Json -DateKind String).records_emitted
    $taskRunCount = 0
    foreach ($taskLine in Get-Content -LiteralPath $taskCanonicalPath) {
        if (-not $taskLine) { throw 'Blank canonical JSONL line' }
        $taskSchema = Invoke-SchemaValidation -Json $taskLine
        if (-not $taskSchema.IsValid) { throw "E2E schema failure: $($taskSchema.Detail)" }
        $taskParsed = $taskLine | ConvertFrom-Json -Depth 100 -DateKind String
        $taskSemantics = Test-CanonicalSemantics -Observation $taskParsed
        if (-not $taskSemantics.IsValid) { throw "E2E semantic failure: $($taskSemantics.Detail)" }
        $taskRecordsPassed += 1
        $taskRunCount += 1
    }
    if ($taskRunCount -ne $taskExpectedCount) { throw 'E2E emitted-count mismatch' }
}
if ($taskRecordsPassed -eq 0) { throw 'E2E contract qualification requires positive evidence' }
Write-Host "E2E JSONL SCHEMA+SEMANTICS PASS=$taskRecordsPassed FAIL=0 RUNS=$($RunDirectories.Count)"
