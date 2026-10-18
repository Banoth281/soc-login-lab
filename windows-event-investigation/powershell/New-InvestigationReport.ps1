# Reads an existing lab CSV. Does not query Windows logs or generate login attempts.
param(
    [string]$CsvPath = (Join-Path $env:USERPROFILE 'SOC-Lab-Reports\lab-failed-logons.csv'),
    [string]$OutputPath = (Join-Path $env:USERPROFILE 'SOC-Lab-Reports\investigation-report.html')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Find-RepeatedFailures.ps1')
$records = @(Import-Csv -LiteralPath $CsvPath)
$required = @('TimeUTC','RecordID','Account','SourceIP','LogonType','Status','SubStatus')
if ($records.Count -eq 0) { throw 'CSV has no event rows.' }
foreach ($column in $required) {
    if ($records[0].PSObject.Properties.Name -notcontains $column) {
        throw "Missing CSV column: $column"
    }
}
foreach ($record in $records) {
    if ([string]::IsNullOrWhiteSpace($record.Account) -or
        [string]::IsNullOrWhiteSpace($record.SourceIP)) {
        throw 'Account and SourceIP must be populated.'
    }
    $record.TimeUTC = [datetimeoffset]::Parse(
        $record.TimeUTC,
        [Globalization.CultureInfo]::InvariantCulture
    ).UtcDateTime
}
$alerts = @(Find-RepeatedFailures -Records $records)
$eventRows = $records | Select-Object @{
    Name='TimeUTC'; Expression={$_.TimeUTC.ToString('o')}
},RecordID,Account,SourceIP,LogonType,Status,SubStatus
$eventsHtml = ($eventRows | ConvertTo-Html -Fragment) -join [Environment]::NewLine
if ($alerts.Count -gt 0) {
    $alertsHtml = ($alerts | ConvertTo-Html -Fragment) -join [Environment]::NewLine
} else {
    $alertsHtml = '<p>No account/source pair met the configured threshold in the supplied records.</p>'
}
$generated = [datetime]::UtcNow.ToString('u')
$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows Failed-Logon Investigation</title>
<style>
body{font:16px/1.6 system-ui,sans-serif;background:#f1f5f9;color:#172033;margin:0;padding:32px}
main{max-width:1200px;margin:auto;background:white;padding:32px;border-radius:12px}
h1,h2{color:#12345a} .summary{padding:16px;background:#e8f3f5;border-left:4px solid #087e8b}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border:1px solid #d8e0e9;padding:10px;text-align:left}
th{background:#12345a;color:white}.table-wrap{overflow-x:auto}
small{color:#526176}@media print{body{padding:0;background:white}main{padding:0}}
</style>
</head>
<body><main>
<h1>Windows Failed-Logon Investigation</h1>
<p>Local lab evidence review and repeated-failure analysis</p>
<div class="summary"><strong>Events imported: $($records.Count)</strong> |
<strong>Threshold alerts: $($alerts.Count)</strong><br>
Rule: at least 5 failures for the same account and source IP within an inclusive 5-minute window.</div>
<h2>Detection findings</h2><div class="table-wrap">$alertsHtml</div>
<h2>Collected events</h2><div class="table-wrap">$eventsHtml</div>
<h2>Interpretation and limits</h2>
<p>Zero alerts means the threshold was not reached in this CSV; it does not establish that a system is secure.
An alert identifies a pattern requiring investigation, not a confirmed attack.
The analysis assumes records are unique and from one host/domain. One alert is emitted per account/source pair per report.
This is an on-demand report, not continuous monitoring.</p>
<p>Input is a local CSV; no independent verification of its origin is performed.
Review account names and addresses before sharing this report.</p>
<small>Generated UTC: $generated | Event timestamps shown in UTC</small>
</main></body></html>
"@
$destination = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $destination
if (-not (Test-Path -LiteralPath $parent)) { throw "Output folder does not exist: $parent" }
$html | Set-Content -LiteralPath $destination -Encoding UTF8
Write-Output "Events imported: $($records.Count)"
Write-Output "Threshold alerts: $($alerts.Count)"
Write-Output "Report saved: $destination"
