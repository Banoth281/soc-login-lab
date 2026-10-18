# Synthetic tests only. No Security-log access or administrator rights required.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Find-RepeatedFailures.ps1')
$base = [datetime]::SpecifyKind([datetime]'2026-01-01T00:00:00', [DateTimeKind]::Utc)

$script:sequence = 0
function New-Fixture {
    param([int[]]$Seconds, [string]$Account = 'SYNTHETIC_User', [string]$SourceIP = '192.0.2.10')
    foreach ($second in $Seconds) {
        $script:sequence++
        [pscustomobject]@{
            TimeUTC = $base.AddSeconds($second).ToString('o')
            RecordID = $script:sequence
            Computer = 'LAB-HOST'
            Domain = 'LAB'
            Channel = 'Security'
            EventID = 4625
            LogonType = '3'
            Status = '0xc000006d'
            SubStatus = '0xc0000064'
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


function Assert-Equal($Actual,$Expected) {
    if($Actual -ne $Expected){throw "Expected [$Expected], received [$Actual]"}
}
function Assert-Rejected([scriptblock]$Action,[string]$Message='') {
    $caught=$false
    try { & $Action | Out-Null } catch {
        $caught=$true
        if($Message -and $_.Exception.Message -notlike "*$Message*"){throw "Wrong rejection: $($_.Exception.Message)"}
    }
    if(-not $caught){throw 'Expected rejection'}
}
$extraTests=@(
    @{Name='Destination host isolation'; Run={
        $r=@(New-Fixture @(0,30,60,90,120)); $r[0].Computer='OTHER'; $r[1].Computer='OTHER'
        Assert-Equal @(Find-RepeatedFailures $r).Count 0
    }},
    @{Name='Domain isolation'; Run={
        $r=@(New-Fixture @(0,30,60,90,120)); $r[0].Domain='OTHER'; $r[1].Domain='OTHER'
        Assert-Equal @(Find-RepeatedFailures $r).Count 0
    }},
    @{Name='Duplicate copies cannot inflate threshold'; Run={
        $r=@(New-Fixture @(0,30,60,90))
        Assert-Equal @(Find-RepeatedFailures ($r+$r+$r)).Count 0
        Assert-Equal @(ConvertTo-FailedLogonRecords ($r+$r)).Count 4
    }},
    @{Name='Positive duplicate set retains five evidence IDs'; Run={
        $r=@(New-Fixture @(0,30,60,90,120)); $a=@(Find-RepeatedFailures ($r+$r))
        Assert-Equal $a.Count 1; Assert-Equal $a[0].Failures 5
        Assert-Equal ($a[0].RecordIDs -join ',') ($r.RecordID -join ',')
        Assert-Equal $a[0].Computer 'LAB-HOST'; Assert-Equal $a[0].Domain 'LAB'
        Assert-Equal $a[0].FirstUTC $r[0].TimeUTC; Assert-Equal $a[0].LastUTC $r[4].TimeUTC
    }},
    @{Name='Conflicting duplicate identity rejected'; Run={
        $r=@(New-Fixture @(0)); $copy=$r[0]|Select-Object *; $copy.Account='CONFLICT'
        Assert-Rejected { ConvertTo-FailedLogonRecords @($r[0],$copy) } 'Conflicting'
    }},
    @{Name='Reused record ID at later timestamp retained'; Run={
        $r=@(New-Fixture @(0,30,60,90,120)); foreach($e in $r){$e.RecordID=10}
        Assert-Equal @(Find-RepeatedFailures $r).Count 1
    }},
    @{Name='Legacy missing host rejected'; Run={
        $r=@(New-Fixture @(0)); $r[0].PSObject.Properties.Remove('Computer')
        Assert-Rejected { Find-RepeatedFailures $r } 'Computer'
    }},
    @{Name='Missing domain rejected'; Run={
        $r=@(New-Fixture @(0)); $r[0].Domain=''
        Assert-Rejected { Find-RepeatedFailures $r } 'Domain'
    }},
    @{Name='Malformed source IP rejected'; Run={
        $r=@(New-Fixture @(0)); $r[0].SourceIP='invalid'
        Assert-Rejected { Find-RepeatedFailures $r } 'SourceIP'
    }},
    @{Name='Unavailable source IP rejected'; Run={
        $r=@(New-Fixture @(0)); $r[0].SourceIP='-'
        Assert-Rejected { Find-RepeatedFailures $r } 'SourceIP'
    }},
    @{Name='Naive timestamp rejected'; Run={
        $r=@(New-Fixture @(0)); $r[0].TimeUTC='2026-01-01T00:00:00'
        Assert-Rejected { Find-RepeatedFailures $r } 'timezone'
    }},
    @{Name='Malformed timestamp rejected'; Run={
        $r=@(New-Fixture @(0)); $r[0].TimeUTC='2026-99-01T00:00:00Z'
        Assert-Rejected { Find-RepeatedFailures $r } 'timestamp'
    }},
    @{Name='Equivalent timezone duplicate normalised'; Run={
        $r=@(New-Fixture @(0)); $copy=$r[0]|Select-Object *; $copy.TimeUTC='2026-01-01T01:00:00+01:00'
        Assert-Equal @(ConvertTo-FailedLogonRecords @($r[0],$copy)).Count 1
    }},
    @{Name='Equivalent IPv6 addresses grouped'; Run={
        $r=@(New-Fixture @(0,30,60,90,120) -SourceIP '2001:db8::1')
        $r[0].SourceIP='2001:0db8:0:0:0:0:0:1'
        Assert-Equal @(Find-RepeatedFailures $r).Count 1
    }},
    @{Name='Windows name case grouped'; Run={
        $r=@(New-Fixture @(0,30,60,90,120)); $r[0].Computer='lab-host'
        $r[0].Domain='lab'; $r[0].Account='synthetic_user'
        Assert-Equal @(Find-RepeatedFailures $r).Count 1
    }},
    @{Name='Invalid record ID rejected'; Run={
        $r=@(New-Fixture @(0)); $r[0].RecordID=-1
        Assert-Rejected { Find-RepeatedFailures $r } 'RecordID'
    }},
    @{Name='Wrong event type rejected'; Run={
        $r=@(New-Fixture @(0)); $r[0].EventID=4624
        Assert-Rejected { Find-RepeatedFailures $r } '4625'
    }},
    @{Name='Threshold below two rejected'; Run={
        Assert-Rejected { Find-RepeatedFailures @() -Threshold 1 }
    }},
    @{Name='Zero window rejected'; Run={
        Assert-Rejected { Find-RepeatedFailures @() -WindowMinutes 0 }
    }},
    @{Name='Custom threshold and window'; Run={
        Assert-Equal @(Find-RepeatedFailures @(New-Fixture @(0,30,60)) -Threshold 3 -WindowMinutes 1).Count 1
    }},
    @{Name='Later rolling window found'; Run={
        $r=@(New-Fixture @(0,600,630,660,690,720)); $a=@(Find-RepeatedFailures $r)
        Assert-Equal $a.Count 1; Assert-Equal $a[0].Failures 5
        Assert-Equal $a[0].FirstUTC $r[1].TimeUTC
    }},
    @{Name='HTML report counts context and safe text'; Run={
        $temp=Join-Path ([IO.Path]::GetTempPath()) ('windows-v2-'+[guid]::NewGuid())
        New-Item -ItemType Directory -Path $temp | Out-Null
        try {
            $r=@(New-Fixture @(0,30,60,90,120) -Account '<script>alert(1)</script>')
            $csv=Join-Path $temp 'events.csv'; $html=Join-Path $temp 'report.html'
            ($r+$r)|Export-Csv $csv -NoTypeInformation -Encoding UTF8
            & (Join-Path $PSScriptRoot 'New-InvestigationReport.ps1') -CsvPath $csv -OutputPath $html | Out-Null
            $text=Get-Content $html -Raw
            if($text -notmatch 'Duplicates removed: 5' -or $text -notmatch 'Threshold alerts: 1'){throw 'Wrong report counts'}
            if($text -match '<script>' -or $text -notmatch '&lt;script&gt;'){throw 'Unsafe evidence encoding'}
            if($text -notmatch 'LAB-HOST'){throw 'Missing host context'}
            Assert-Rejected { & (Join-Path $PSScriptRoot 'New-InvestigationReport.ps1') -CsvPath $csv -OutputPath $csv } 'overwrite'
        } finally { Remove-Item $temp -Recurse -Force }
    }}
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

$extraTests += @{Name='Relative report paths use PowerShell location'; Run={
    $temp=Join-Path ([IO.Path]::GetTempPath()) ('windows-relative-'+[guid]::NewGuid())
    New-Item -ItemType Directory -Path $temp | Out-Null
    $generator=Join-Path $PSScriptRoot 'New-InvestigationReport.ps1'
    try {
        @(New-Fixture @(0,30)) | Export-Csv (Join-Path $temp 'events.csv') -NoTypeInformation -Encoding UTF8
        Push-Location $temp
        try {
            & $generator -CsvPath './events.csv' -OutputPath './relative-report.html' | Out-Null
            if(-not (Test-Path -LiteralPath (Join-Path $temp 'relative-report.html'))){throw 'Report not saved in PowerShell folder'}
            Assert-Rejected { & $generator -CsvPath './events.csv' -OutputPath './events.csv' } 'overwrite'
        } finally { Pop-Location }
    } finally { Remove-Item -LiteralPath $temp -Recurse -Force }
}}

foreach($test in $extraTests) {
    try { & $test.Run; Write-Output "PASS: $($test.Name)" }
    catch { $failed++; Write-Output "FAIL: $($test.Name) - $($_.Exception.Message)" }
}
$total=$tests.Count+$extraTests.Count
Write-Output "$($total-$failed)/$total tests passed"
if ($failed -gt 0) { throw "$failed detector test(s) failed" }
