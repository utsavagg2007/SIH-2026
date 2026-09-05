[CmdletBinding()]
param(
    [string]$PythonExecutable = "python"
)

$ErrorActionPreference = "Stop"
$Image = "zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
$SensorId = "m1d-e2e-sensor"
$ObservedAt = "2026-01-02T03:04:05.678901Z"
$ExpectedOrder = @("flow", "flow", "flow", "flow", "dns", "dns", "tls", "http", "http")
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$IngestionRoot = Split-Path -Parent $ScriptRoot
$RepositoryRoot = Split-Path -Parent $IngestionRoot
$FixtureDirectory = Join-Path $ScriptRoot "fixtures\pcap"
$Fixture = Join-Path $FixtureDirectory "m1d_synthetic.pcap"
$Schema = Join-Path $RepositoryRoot "contracts\canonical_observation_v1.schema.json"
$HeaderEvidence = Join-Path $ScriptRoot "fixtures\runtime_headers\zeek_8.0.10_m1d_fields.txt"
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sih-m1d-docker-e2e-" + [guid]::NewGuid().ToString("N"))
$OriginalPythonPath = $env:PYTHONPATH
$OriginalPyo3Python = $env:PYO3_PYTHON

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "ASSERTION FAILED: $Message"
    }
}

function Assert-BytesEqual([string]$Left, [string]$Right, [string]$Message) {
    $leftBytes = [System.IO.File]::ReadAllBytes($Left)
    $rightBytes = [System.IO.File]::ReadAllBytes($Right)
    Assert-True ([System.Linq.Enumerable]::SequenceEqual[byte]($leftBytes, $rightBytes)) $Message
}

function Invoke-PinnedZeek([string]$PcapDirectory, [string]$PcapName, [string]$OutputDirectory, [bool]$ExpectSuccess = $true) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    & docker run --rm --platform linux/amd64 `
        -v "${PcapDirectory}:/pcaps:ro" `
        -v "${OutputDirectory}:/logs" `
        -w /logs `
        $Image zeek -D -C -r "/pcaps/$PcapName" local
    $exitCode = $LASTEXITCODE
    if ($ExpectSuccess) {
        Assert-True ($exitCode -eq 0) "pinned Zeek failed for $PcapName (exit $exitCode)"
    } else {
        Assert-True ($exitCode -ne 0) "pinned Zeek unexpectedly accepted invalid fixture $PcapName"
    }
    return $exitCode
}

function Invoke-Canonicalize([string]$LogDirectory, [string]$Output, [string]$Sha256, [bool]$AllowEmpty) {
    $driver = @'
import ingestion_core
import sys
print(ingestion_core.write_canonical_observations_from_zeek_logs(
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6] == "true"
))
'@
    $allow = if ($AllowEmpty) { "true" } else { "false" }
    $summary = & $PythonExecutable -c $driver $LogDirectory $Output $SensorId $Sha256 $ObservedAt $allow
    Assert-True ($LASTEXITCODE -eq 0) "canonicalization failed for $LogDirectory"
    return ($summary | Select-Object -Last 1 | ConvertFrom-Json)
}

function Get-ZeekUids([string]$LogDirectory) {
    $uids = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @("conn.log", "dns.log", "ssl.log", "http.log")) {
        $path = Join-Path $LogDirectory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $fields = $null
        foreach ($line in [System.IO.File]::ReadAllLines($path)) {
            if ($line.StartsWith("#fields`t")) {
                $fields = $line.Substring(8).Split("`t")
                continue
            }
            if ($line.StartsWith("#") -or [string]::IsNullOrEmpty($line)) { continue }
            $uidIndex = [array]::IndexOf($fields, "uid")
            Assert-True ($uidIndex -ge 0) "$name runtime header has no uid field"
            $columns = $line.Split("`t")
            $uids.Add("${name}:$($columns[$uidIndex])")
        }
    }
    return $uids.ToArray()
}

function Assert-RuntimeHeaders([string]$LogDirectory) {
    $evidence = ([System.IO.File]::ReadAllText($HeaderEvidence) -replace "`r`n", "`n")
    foreach ($name in @("conn.log", "dns.log", "ssl.log", "http.log")) {
        $path = Join-Path $LogDirectory $name
        $fieldLine = [System.IO.File]::ReadAllLines($path) | Where-Object { $_.StartsWith("#fields`t") } | Select-Object -First 1
        Assert-True ($null -ne $fieldLine) "$name has no #fields header"
        Assert-True $evidence.Contains("$name`n$fieldLine") "$name #fields header drifted from qualification evidence"
    }
}

function Read-And-ValidateCanonical([string]$Path) {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        if ([string]::IsNullOrEmpty($line)) { continue }
        $schemaErrors = @()
        $valid = Test-Json -Json $line -SchemaFile $Schema -ErrorAction SilentlyContinue -ErrorVariable schemaErrors
        if (-not $valid) {
            throw "schema validation failed for ${Path}: $($schemaErrors -join '; ')"
        }
        $rows.Add(($line | ConvertFrom-Json))
    }
    return $rows.ToArray()
}

function Assert-CanonicalShape([object[]]$Rows) {
    Assert-True ($Rows.Count -eq 9) "expected 9 canonical observations, got $($Rows.Count)"
    $actualOrder = @($Rows | ForEach-Object { $_.observation_type })
    Assert-True (($actualOrder -join ",") -eq ($ExpectedOrder -join ",")) "canonical type order mismatch"
    Assert-True ((@($Rows | Where-Object observation_type -eq "flow")).Count -eq 4) "flow count is not 4"
    Assert-True ((@($Rows | Where-Object observation_type -eq "dns")).Count -eq 2) "DNS count is not 2"
    Assert-True ((@($Rows | Where-Object observation_type -eq "tls")).Count -eq 1) "TLS count is not 1"
    Assert-True ((@($Rows | Where-Object observation_type -eq "http")).Count -eq 2) "HTTP count is not 2"
    $uris = @($Rows | Where-Object observation_type -eq "http" | ForEach-Object { $_.data.uri })
    Assert-True (($uris -join ",") -eq "/one,/two") "HTTP one-to-many rows were not independently preserved"
}

function Assert-DataMinimized([string]$Path) {
    $text = [System.IO.File]::ReadAllText($Path)
    foreach ($forbidden in @(
        '"username":', '"password":', '"authorization":', '"cookie":', '"set-cookie":',
        '"referrer":', '"trans_depth":', '"request_body":', '"response_body":',
        '"cert_chain":', '"certificate_subject":', '"certificate_issuer":',
        '"filename":', '"mime_type":', '"answers":', '"ttls":'
    )) {
        Assert-True (-not $text.ToLowerInvariant().Contains($forbidden)) "canonical artifact contains forbidden source field $forbidden"
    }
    foreach ($discardedSourceValue in @("203.0.113.10", "203.0.113.11")) {
        Assert-True (-not $text.Contains($discardedSourceValue)) "canonical artifact leaked full DNS answer value $discardedSourceValue"
    }
}

try {
    New-Item -ItemType Directory -Path $TempRoot | Out-Null

    # Rebuild the importable binding without installing anything globally.
    $resolvedPython = (& $PythonExecutable -c "import sys; print(sys.executable)" | Select-Object -Last 1).Trim()
    Assert-True (-not [string]::IsNullOrWhiteSpace($resolvedPython)) "could not resolve -PythonExecutable"
    $env:PYO3_PYTHON = $resolvedPython
    Push-Location $IngestionRoot
    try {
        & cargo build --locked --features extension-module
        Assert-True ($LASTEXITCODE -eq 0) "cargo extension build failed"
    } finally {
        Pop-Location
    }
    $moduleDirectory = Join-Path $TempRoot "python-module"
    New-Item -ItemType Directory -Path $moduleDirectory | Out-Null
    if ($IsWindows) {
        Copy-Item -LiteralPath (Join-Path $IngestionRoot "target\debug\ingestion_core.dll") -Destination (Join-Path $moduleDirectory "ingestion_core.pyd")
    } else {
        Copy-Item -LiteralPath (Join-Path $IngestionRoot "target/debug/libingestion_core.so") -Destination (Join-Path $moduleDirectory "ingestion_core.so")
    }
    $env:PYTHONPATH = if ([string]::IsNullOrEmpty($OriginalPythonPath)) { $moduleDirectory } else { "$moduleDirectory$([IO.Path]::PathSeparator)$OriginalPythonPath" }

    # Verify every checked-in PCAP is exactly reproducible from the generator.
    $generated = Join-Path $TempRoot "generated"
    New-Item -ItemType Directory -Path $generated | Out-Null
    & $PythonExecutable (Join-Path $IngestionRoot "scripts\generate_synthetic_pcap.py") `
        --output (Join-Path $generated "m1d_synthetic.pcap") `
        --auxiliary-directory $generated
    Assert-True ($LASTEXITCODE -eq 0) "fixture generator failed"
    foreach ($name in @("m1d_synthetic.pcap", "m1d_empty.pcap", "m1d_invalid_truncated.pcap", "m1d_unsupported_arp.pcap")) {
        Assert-BytesEqual (Join-Path $FixtureDirectory $name) (Join-Path $generated $name) "generator drift for $name"
        Assert-BytesEqual (Join-Path $FixtureDirectory ($name + ".sha256")) (Join-Path $generated ($name + ".sha256")) "digest sidecar drift for $name"
    }

    $sha = (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash.ToLowerInvariant()
    $runA = Join-Path $TempRoot "run-a"
    $runB = Join-Path $TempRoot "run-b"
    $relocated = Join-Path $TempRoot "relocated-pcap"
    $runC = Join-Path $TempRoot "run-c"
    New-Item -ItemType Directory -Path $relocated | Out-Null
    $renamedPcap = Join-Path $relocated "same-bytes-renamed.pcap"
    Copy-Item -LiteralPath $Fixture -Destination $renamedPcap
    Assert-True ($sha -eq (Get-FileHash -LiteralPath $renamedPcap -Algorithm SHA256).Hash.ToLowerInvariant()) "relocated PCAP SHA changed"

    Invoke-PinnedZeek $FixtureDirectory "m1d_synthetic.pcap" $runA | Out-Null
    Invoke-PinnedZeek $FixtureDirectory "m1d_synthetic.pcap" $runB | Out-Null
    Invoke-PinnedZeek $relocated "same-bytes-renamed.pcap" $runC | Out-Null
    Assert-RuntimeHeaders $runA
    Assert-RuntimeHeaders $runB
    Assert-RuntimeHeaders $runC

    $canonicalA = Join-Path $TempRoot "canonical-a.jsonl"
    $canonicalB = Join-Path $TempRoot "canonical-b.jsonl"
    $canonicalC = Join-Path $TempRoot "canonical-c.jsonl"
    $summaryA = Invoke-Canonicalize $runA $canonicalA $sha $false
    $summaryB = Invoke-Canonicalize $runB $canonicalB $sha $false
    $summaryC = Invoke-Canonicalize $runC $canonicalC $sha $false
    foreach ($summary in @($summaryA, $summaryB, $summaryC)) {
        Assert-True ($summary.flow_emitted -eq 4) "summary flow count mismatch"
        Assert-True ($summary.dns_emitted -eq 2) "summary DNS count mismatch"
        Assert-True ($summary.tls_emitted -eq 1) "summary TLS count mismatch"
        Assert-True ($summary.http_emitted -eq 2) "summary HTTP count mismatch"
        Assert-True ($summary.rows_skipped -eq 0) "summary unexpectedly skipped rows"
    }
    $rowsA = @(Read-And-ValidateCanonical $canonicalA)
    $rowsB = @(Read-And-ValidateCanonical $canonicalB)
    $rowsC = @(Read-And-ValidateCanonical $canonicalC)
    Assert-CanonicalShape $rowsA
    Assert-CanonicalShape $rowsB
    Assert-CanonicalShape $rowsC
    Assert-DataMinimized $canonicalA

    # True integrated seam: the same pinned-Zeek logs must produce the
    # explicitly versioned detector profile, pass the real adapter, and run
    # every currently available detector without touching canonical evidence.
    $canonicalBeforeDetector = (Get-FileHash -LiteralPath $canonicalA -Algorithm SHA256).Hash
    $detectorFeatures = Join-Path $TempRoot "detector-v2-features.jsonl"
    $seamCanonical = Join-Path $TempRoot "seam-canonical.jsonl"
    & $PythonExecutable (Join-Path $IngestionRoot "pipeline.py") $Fixture `
        --skip-zeek `
        --keep-logs $runA `
        --output $detectorFeatures `
        --feature-profile detector-v2 `
        --canonical-output $seamCanonical `
        --sensor-id $SensorId `
        --stats
    Assert-True ($LASTEXITCODE -eq 0) "detector-v2 ingestion profile failed"
    Assert-True ($canonicalBeforeDetector -eq (Get-FileHash -LiteralPath $canonicalA -Algorithm SHA256).Hash) "detector feature production changed canonical evidence"

    $featureRows = @([System.IO.File]::ReadAllLines($detectorFeatures) | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-True ($featureRows.Count -eq 4) "detector-v2 did not emit all four flows"
    Assert-True ((@($featureRows | Where-Object { $null -ne $_.timestamp })).Count -eq 4) "detector-v2 omitted event timestamps"
    Assert-True ((@($featureRows | Where-Object { $null -ne $_.dns.query })).Count -ge 1) "detector-v2 omitted DNS query evidence"
    Assert-True ((@($featureRows | Where-Object { $null -ne $_.tls.version })).Count -eq 1) "detector-v2 omitted TLS evidence"
    Assert-True ((@($featureRows | Where-Object { $null -ne $_.http.uri })).Count -eq 1) "detector-v2 omitted HTTP evidence"
    $seamRows = @(Read-And-ValidateCanonical $seamCanonical)
    Assert-CanonicalShape $seamRows

    $adapterDriver = @'
import json
import sys
from detection_core.adapters import IngestionJsonlAdapter
adapter = IngestionJsonlAdapter(path=sys.argv[1], strict=True)
events = list(adapter)
print(json.dumps({"parsed": adapter.stats.parsed, "errors": adapter.stats.errors, "uids": [event.uid for event in events]}))
'@
    $adapterSummary = (& $PythonExecutable -c $adapterDriver $detectorFeatures | Select-Object -Last 1 | ConvertFrom-Json)
    Assert-True ($LASTEXITCODE -eq 0) "real detection adapter rejected detector-v2 output"
    Assert-True ($adapterSummary.parsed -eq 4) "adapter did not accept all four detector-v2 flows"
    Assert-True ($adapterSummary.errors -eq 0) "adapter reported detector-v2 errors"

    $detectorAlerts = Join-Path $TempRoot "detector-alerts.jsonl"
    & $PythonExecutable -m detection_core.runner $detectorFeatures --output $detectorAlerts --quiet
    Assert-True ($LASTEXITCODE -eq 0) "detection runner failed on real PCAP-derived features"
    Assert-True ((@([System.IO.File]::ReadAllLines($detectorAlerts))).Count -eq 0) "small deterministic fixture unexpectedly triggered an alert"

    Assert-True (((Get-ZeekUids $runA) -join "|") -eq ((Get-ZeekUids $runB) -join "|")) "A/B source UIDs differ"
    Assert-True (((Get-ZeekUids $runA) -join "|") -eq ((Get-ZeekUids $runC) -join "|")) "A/C source UIDs differ"
    Assert-True ((($rowsA.record_id) -join "|") -eq (($rowsB.record_id) -join "|")) "A/B record IDs differ"
    Assert-True ((($rowsA.record_id) -join "|") -eq (($rowsC.record_id) -join "|")) "A/C record IDs differ"
    $flowLinksA = @($rowsA | ForEach-Object { $_.data.flow_record_id } | Where-Object { $null -ne $_ })
    $flowLinksC = @($rowsC | ForEach-Object { $_.data.flow_record_id } | Where-Object { $null -ne $_ })
    Assert-True (($flowLinksA -join "|") -eq ($flowLinksC -join "|")) "A/C flow_record_id values differ"
    Assert-BytesEqual $canonicalA $canonicalB "fixed-clock A/B canonical bytes differ"
    Assert-BytesEqual $canonicalA $canonicalC "renamed-path canonical bytes differ"
    $canonicalText = [System.IO.File]::ReadAllText($canonicalA)
    Assert-True (-not $canonicalText.Contains("m1d_synthetic.pcap")) "source filename leaked into canonical artifact"
    Assert-True (-not $canonicalText.Contains("same-bytes-renamed.pcap")) "relocated filename leaked into canonical artifact"

    foreach ($case in @(
        @{ Name = "m1d_empty.pcap"; Directory = "empty" },
        @{ Name = "m1d_unsupported_arp.pcap"; Directory = "unsupported" }
    )) {
        $logs = Join-Path $TempRoot $case.Directory
        Invoke-PinnedZeek $FixtureDirectory $case.Name $logs | Out-Null
        $caseSha = (Get-FileHash -LiteralPath (Join-Path $FixtureDirectory $case.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
        $output = Join-Path $TempRoot ($case.Directory + ".jsonl")
        $summary = Invoke-Canonicalize $logs $output $caseSha $true
        Assert-True ((Get-Item -LiteralPath $output).Length -eq 0) "$($case.Name) canonical output is not zero bytes"
        Assert-True (($summary.flow_emitted + $summary.dns_emitted + $summary.tls_emitted + $summary.http_emitted) -eq 0) "$($case.Name) unexpectedly emitted supported observations"
    }

    $invalidLogs = Join-Path $TempRoot "invalid"
    Invoke-PinnedZeek $FixtureDirectory "m1d_invalid_truncated.pcap" $invalidLogs $false | Out-Null
    $invalidCanonical = Join-Path $TempRoot "invalid.jsonl"
    Assert-True (-not (Test-Path -LiteralPath $invalidCanonical)) "invalid PCAP produced canonical final artifact"
    Assert-True (-not (Get-ChildItem -LiteralPath $TempRoot -Recurse -File | Where-Object { $_.Name -like "*.tmp" -or $_.Name -like "*.canonical.lock" })) "invalid-PCAP path left canonical temp/lock residue"

    Write-Output "PASS fixture generator: final and auxiliary PCAP bytes reproduced"
    Write-Output "PASS pinned Docker replay: A/B/C UIDs, record IDs, flow links, order, and bytes identical"
    Write-Output "PASS runtime headers: conn/dns/ssl/http exact qualification match"
    Write-Output "PASS schema: 27/27 replay lines valid (9 per A/B/C)"
    Write-Output "PASS counts: flow=4 dns=2 tls=1 http=2 total=9"
    Write-Output "PASS empty and ARP-only: zero-byte canonical output"
    Write-Output "PASS invalid truncated PCAP: Zeek nonzero, no canonical artifact or residue"
    Write-Output "PASS data minimization and path independence"
    Write-Output "PASS real seam: one workflow emitted detector-v2 + canonical (4/2/1/2), adapter (4/4), detectors (0 expected alerts)"
} finally {
    $env:PYTHONPATH = $OriginalPythonPath
    $env:PYO3_PYTHON = $OriginalPyo3Python
    if (Test-Path -LiteralPath $TempRoot) {
        $resolvedTemp = [System.IO.Path]::GetFullPath($TempRoot)
        $systemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if (-not $resolvedTemp.StartsWith($systemTemp, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "refusing to clean E2E directory outside the system temp root: $resolvedTemp"
        }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}
