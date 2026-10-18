# Synthetic tests only. No Security-log access or administrator rights required.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Find-RepeatedFailures.ps1')
$base = [datetime]::SpecifyKind([datetime]'2026-01-01T00:00:00', [DateTimeKind]::Utc)

function New-Fixture {
    param([int[]]$Seconds, [string]$Account = 'SYNTHETIC_User', [string]$SourceIP = '192.0.2.10')
    foreach ($second in $Seconds) {
        [pscustomobject]@{
            TimeUTC = $base.AddSeconds($second)
            Account = $Account
            SourceIP = $SourceIP
        }
    }
}

$tests = @(
    @{Name='Five failures trigger'; Records=@(New-Fixture @(0,30,60,90,120)); Expected=1},
    @{Name='Four failures do not trigger'; Records=@(New-Fixture @(0,30,60,90)); Expected=0},
    @{Name='Inclusive 300-second boundary'; Records=@(New-Fixture @(0,60,120,180,300)); Expected=1},
    @{Name='301 seconds is outside window'; Records=@(New-Fixture @(0,60,120,180,301)); Expected=0},
    @{Name='Sources remain separate'; Records=@(
        (New-Fixture @(0,30,60) -SourceIP '192.0.2.10')
        (New-Fixture @(90,120) -SourceIP '192.0.2.20')
    ); Expected=0},
    @{Name='Accounts remain separate'; Records=@(
        (New-Fixture @(0,30,60) -Account 'SYNTHETIC_A')
        (New-Fixture @(90,120) -Account 'SYNTHETIC_B')
    ); Expected=0},
    @{Name='Unsorted input works'; Records=@(New-Fixture @(120,0,90,30,60)); Expected=1},
    @{Name='Empty input gives no alerts'; Records=@(); Expected=0}
)

$failed = 0
foreach ($test in $tests) {
    try {
        $actual = @(Find-RepeatedFailures -Records $test.Records)
        if ($actual.Count -ne $test.Expected) {
            throw "Expected $($test.Expected) alert(s); got $($actual.Count)"
        }
        if ($actual.Count -eq 1) {
            if ($actual[0].Failures -ne 5 -or
                $actual[0].Account -ne 'SYNTHETIC_User' -or
                $actual[0].SourceIP -ne '192.0.2.10') {
                throw 'Alert count matched but alert details were incorrect'
            }
        }
        Write-Output "PASS: $($test.Name)"
    } catch {
        $failed++
        Write-Output "FAIL: $($test.Name) - $($_.Exception.Message)"
    }
}
Write-Output "$($tests.Count - $failed)/$($tests.Count) tests passed"
if ($failed -gt 0) { throw "$failed detector test(s) failed" }
