[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$contractsDirectory = Split-Path -Parent $PSScriptRoot
$schemaPath = Join-Path $contractsDirectory 'canonical_observation_v1.schema.json'
$validDirectory = Join-Path $contractsDirectory 'fixtures/valid'
$invalidDirectory = Join-Path $contractsDirectory 'fixtures/invalid'
$semanticInvalidDirectory = Join-Path $contractsDirectory 'fixtures/semantic-invalid'

$script:passed = 0
$script:failed = 0

function Write-ContractResult {
    param(
        [Parameter(Mandatory)] [bool] $Condition,
        [Parameter(Mandatory)] [string] $Name,
        [string] $Detail = ''
    )

    if ($Condition) {
        $script:passed += 1
        Write-Host "PASS $Name"
        return
    }

    $script:failed += 1
    if ($Detail) {
        Write-Host "FAIL $Name - $Detail"
    } else {
        Write-Host "FAIL $Name"
    }
}

function Read-JsonFixture {
    param([Parameter(Mandatory)] [string] $FixturePath)

    if (-not (Test-Path -LiteralPath $FixturePath -PathType Leaf)) {
        throw "Fixture does not exist: $FixturePath"
    }

    $raw = Get-Content -Raw -LiteralPath $FixturePath
    try {
        $parsed = $raw | ConvertFrom-Json -Depth 100 -DateKind String
    } catch {
        throw "Fixture is not syntactically valid JSON: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Raw = $raw
        Parsed = $parsed
    }
}

function Invoke-SchemaValidation {
    param([Parameter(Mandatory)] [string] $Json)

    $validationErrors = @()
    try {
        $isValid = Test-Json `
            -Json $Json `
            -SchemaFile $schemaPath `
            -ErrorAction SilentlyContinue `
            -ErrorVariable validationErrors
    } catch {
        throw "JSON Schema validator invocation failed: $($_.Exception.Message)"
    }

    if ($isValid) {
        if ($validationErrors.Count -gt 0) {
            throw "JSON Schema validator returned success with error records"
        }
        return [pscustomobject]@{ IsValid = $true; Detail = '' }
    }

    if ($validationErrors.Count -eq 0) {
        throw "JSON Schema validator returned failure without a validation diagnostic"
    }

    $unexpectedErrors = @($validationErrors | Where-Object {
        $_.Exception.Message -notlike 'The JSON is not valid with the schema:*'
    })
    if ($unexpectedErrors.Count -gt 0) {
        throw "Unexpected validator error: $($unexpectedErrors[0].Exception.Message)"
    }

    return [pscustomobject]@{
        IsValid = $false
        Detail = $validationErrors[0].Exception.Message
    }
}

function Convert-CanonicalTimestamp {
    param(
        [Parameter(Mandatory)] [object] $Value,
        [Parameter(Mandatory)] [string] $Path
    )

    if ($Value -isnot [string]) {
        return [pscustomobject]@{
            IsValid = $false
            Detail = "$Path is not a string"
        }
    }

    $match = [regex]::Match(
        $Value,
        '^(?<year>[0-9]{4})-(?<month>[0-9]{2})-(?<day>[0-9]{2})T(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})(?:\.(?<fraction>[0-9]+))?Z$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success) {
        return [pscustomobject]@{
            IsValid = $false
            Detail = "$Path is not canonical RFC3339 UTC with a Z suffix"
        }
    }

    $year = [int]$match.Groups['year'].Value
    $month = [int]$match.Groups['month'].Value
    $day = [int]$match.Groups['day'].Value
    $hour = [int]$match.Groups['hour'].Value
    $minute = [int]$match.Groups['minute'].Value
    $second = [int]$match.Groups['second'].Value

    $datePartsAreInRange =
        $year -ge 1 -and $year -le 9999 -and
        $month -ge 1 -and $month -le 12 -and
        $hour -ge 0 -and $hour -le 23 -and
        $minute -ge 0 -and $minute -le 59 -and
        $second -ge 0 -and $second -le 59
    if (-not $datePartsAreInRange) {
        return [pscustomobject]@{
            IsValid = $false
            Detail = "$Path is not an actual calendar date/time: $Value"
        }
    }

    $daysInMonth = [DateTime]::DaysInMonth($year, $month)
    if ($day -lt 1 -or $day -gt $daysInMonth) {
        return [pscustomobject]@{
            IsValid = $false
            Detail = "$Path is not an actual calendar date/time: $Value"
        }
    }

    $wholeSecond = [DateTime]::new(
        $year,
        $month,
        $day,
        $hour,
        $minute,
        $second,
        [DateTimeKind]::Utc
    )

    return [pscustomobject]@{
        IsValid = $true
        Detail = ''
        WholeSecond = $wholeSecond
        Fraction = $match.Groups['fraction'].Value
    }
}

function Compare-CanonicalTimestamps {
    param(
        [Parameter(Mandatory)] [object] $Left,
        [Parameter(Mandatory)] [object] $Right
    )

    $wholeSecondComparison = [DateTime]::Compare($Left.WholeSecond, $Right.WholeSecond)
    if ($wholeSecondComparison -ne 0) {
        return $wholeSecondComparison
    }

    $fractionLength = [Math]::Max($Left.Fraction.Length, $Right.Fraction.Length)
    $leftFraction = $Left.Fraction.PadRight($fractionLength, '0')
    $rightFraction = $Right.Fraction.PadRight($fractionLength, '0')
    return [string]::CompareOrdinal($leftFraction, $rightFraction)
}

function Test-CanonicalSemantics {
    param([Parameter(Mandatory)] [object] $Observation)

    $timestampEntries = @(
        [pscustomobject]@{ Path = 'observed_at'; Value = $Observation.observed_at }
    )

    switch ($Observation.observation_type) {
        'flow' {
            $timestampEntries += [pscustomobject]@{
                Path = 'data.start_time'
                Value = $Observation.data.start_time
            }
            if ($Observation.data.PSObject.Properties.Name -contains 'end_time') {
                $timestampEntries += [pscustomobject]@{
                    Path = 'data.end_time'
                    Value = $Observation.data.end_time
                }
            }
        }
        'dns' {
            $timestampEntries += [pscustomobject]@{
                Path = 'data.event_time'
                Value = $Observation.data.event_time
            }
        }
        'tls' {
            $timestampEntries += [pscustomobject]@{
                Path = 'data.event_time'
                Value = $Observation.data.event_time
            }
        }
        'http' {
            $timestampEntries += [pscustomobject]@{
                Path = 'data.event_time'
                Value = $Observation.data.event_time
            }
        }
    }

    $parsedTimestamps = @{}
    foreach ($entry in $timestampEntries) {
        $timestampResult = Convert-CanonicalTimestamp `
            -Value $entry.Value `
            -Path $entry.Path
        if (-not $timestampResult.IsValid) {
            return [pscustomobject]@{
                IsValid = $false
                Detail = $timestampResult.Detail
            }
        }
        $parsedTimestamps[$entry.Path] = $timestampResult
    }

    if (
        $Observation.observation_type -eq 'flow' -and
        $Observation.data.PSObject.Properties.Name -contains 'end_time'
    ) {
        $comparison = Compare-CanonicalTimestamps `
            -Left $parsedTimestamps['data.end_time'] `
            -Right $parsedTimestamps['data.start_time']
        if ($comparison -lt 0) {
            return [pscustomobject]@{
                IsValid = $false
                Detail = 'data.end_time precedes data.start_time'
            }
        }
    }

    return [pscustomobject]@{ IsValid = $true; Detail = '' }
}

try {
    $schemaDocument = Read-JsonFixture -FixturePath $schemaPath
    $schema = $schemaDocument.Parsed
    Write-ContractResult -Condition $true -Name 'schema is valid JSON'
} catch {
    Write-ContractResult -Condition $false -Name 'schema is valid JSON' -Detail $_.Exception.Message
    Write-Host "TOTAL PASS=$script:passed FAIL=$script:failed"
    exit 1
}

$expectedTypes = @('flow', 'dns', 'tls', 'http')
$actualTypes = @($schema.properties.observation_type.enum)
$typesMatch = ($actualTypes.Count -eq $expectedTypes.Count) -and
    (@(Compare-Object -ReferenceObject $expectedTypes -DifferenceObject $actualTypes).Count -eq 0)
Write-ContractResult -Condition $typesMatch -Name 'v1 observation type set is exactly flow,dns,tls,http'

$qualityPropertyNames = @($schema.'$defs'.quality.properties.PSObject.Properties.Name)
Write-ContractResult -Condition ('lost_bytes' -notin $qualityPropertyNames) -Name 'ambiguous lost_bytes is absent'
Write-ContractResult -Condition ('missed_content_bytes' -in $qualityPropertyNames) -Name 'narrow missed_content_bytes is available'

foreach ($fixture in Get-ChildItem -LiteralPath $validDirectory -Filter '*.json' | Sort-Object Name) {
    try {
        $fixtureDocument = Read-JsonFixture -FixturePath $fixture.FullName
        $schemaResult = Invoke-SchemaValidation -Json $fixtureDocument.Raw
        if (-not $schemaResult.IsValid) {
            Write-ContractResult -Condition $false -Name "valid fixture $($fixture.Name)" -Detail $schemaResult.Detail
            continue
        }

        $semanticResult = Test-CanonicalSemantics -Observation $fixtureDocument.Parsed
        Write-ContractResult `
            -Condition $semanticResult.IsValid `
            -Name "valid fixture $($fixture.Name)" `
            -Detail $semanticResult.Detail
    } catch {
        Write-ContractResult -Condition $false -Name "valid fixture $($fixture.Name)" -Detail $_.Exception.Message
    }
}

foreach ($fixture in Get-ChildItem -LiteralPath $invalidDirectory -Filter '*.json' | Sort-Object Name) {
    try {
        $fixtureDocument = Read-JsonFixture -FixturePath $fixture.FullName
        $schemaResult = Invoke-SchemaValidation -Json $fixtureDocument.Raw
        if ($schemaResult.IsValid) {
            Write-ContractResult -Condition $false -Name "invalid fixture rejected $($fixture.Name)" -Detail 'schema unexpectedly accepted the fixture'
        } else {
            Write-ContractResult -Condition $true -Name "invalid fixture rejected $($fixture.Name)"
        }
    } catch {
        Write-ContractResult -Condition $false -Name "invalid fixture rejected $($fixture.Name)" -Detail $_.Exception.Message
    }
}

foreach ($fixture in Get-ChildItem -LiteralPath $semanticInvalidDirectory -Filter '*.json' | Sort-Object Name) {
    try {
        $fixtureDocument = Read-JsonFixture -FixturePath $fixture.FullName
        $schemaResult = Invoke-SchemaValidation -Json $fixtureDocument.Raw
        if (-not $schemaResult.IsValid) {
            Write-ContractResult -Condition $false -Name "semantic fixture rejected $($fixture.Name)" -Detail "schema rejected before semantic validation: $($schemaResult.Detail)"
            continue
        }

        $semanticResult = Test-CanonicalSemantics -Observation $fixtureDocument.Parsed
        Write-ContractResult `
            -Condition (-not $semanticResult.IsValid) `
            -Name "semantic fixture rejected $($fixture.Name)" `
            -Detail $(if ($semanticResult.IsValid) { 'semantic validator unexpectedly accepted the fixture' } else { '' })
    } catch {
        Write-ContractResult -Condition $false -Name "semantic fixture rejected $($fixture.Name)" -Detail $_.Exception.Message
    }
}

Write-Host "TOTAL PASS=$script:passed FAIL=$script:failed"
if ($script:failed -gt 0) {
    exit 1
}
