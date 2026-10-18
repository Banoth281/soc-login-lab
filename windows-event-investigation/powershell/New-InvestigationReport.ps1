# Reads an existing lab CSV. Does not query Windows logs or generate login attempts.
param(
    [string]$CsvPath = (Join-Path $env:USERPROFILE 'SOC-Lab-Reports\lab-failed-logons.csv'),
    [string]$OutputPath = (Join-Path $env:USERPROFILE 'SOC-Lab-Reports\investigation-report.html'),
    [ValidateRange(2,1000000)][int]$Threshold = 5,
    [ValidateRange(1,10080)][int]$WindowMinutes = 5
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Find-RepeatedFailures.ps1')
$records = @(Import-Csv -LiteralPath $CsvPath)
if ($records.Count -eq 0) { throw 'CSV has no event rows.' }
$importedCount = $records.Count
$records = @(ConvertTo-FailedLogonRecords -Records $records)
$duplicatesRemoved = $importedCount - $records.Count
$alerts = @(Find-RepeatedFailures -Records $records -Threshold $Threshold -WindowMinutes $WindowMinutes)
$eventRows = $records | Select-Object @{
    Name='TimeUTC'; Expression={$_.TimeUTC}
},RecordID,Computer,Domain,Account,SourceIP,LogonType,Status,SubStatus
$eventsHtml = ($eventRows | ConvertTo-Html -Fragment) -join [Environment]::NewLine
if ($alerts.Count -gt 0) {
    $alertsHtml = ($alerts | ConvertTo-Html -Fragment) -join [Environment]::NewLine
} else {
    $alertsHtml = '<p>No host/domain/account/source group met the configured threshold in the supplied records.</p>'
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
<div class="summary"><strong>Events imported: $importedCount</strong> |
<strong>Unique events: $($records.Count)</strong> | Duplicates removed: $duplicatesRemoved |
<strong>Threshold alerts: $($alerts.Count)</strong><br>
Rule: at least $Threshold failures for the same destination host, domain, account and source IP within an inclusive $WindowMinutes-minute window.</div>
<h2>Detection findings</h2><div class="table-wrap">$alertsHtml</div>
<h2>Collected events</h2><div class="table-wrap">$eventsHtml</div>
<h2>Interpretation and limits</h2>
<p>Zero alerts means the threshold was not reached in this CSV; it does not establish that a system is secure.
An alert identifies a pattern requiring investigation, not a confirmed attack.
Input is validated and deduplicated by host, channel, record ID and UTC timestamp. One alert is emitted per host/domain/account/source group per report. Case-insensitive Windows names are grouped together.
This is an on-demand report, not continuous monitoring.</p>
<p>Input is a local CSV; no independent verification of its origin is performed.
Review account names and addresses before sharing this report.</p>
<small>Generated UTC: $generated | Event timestamps shown in UTC</small>
</main></body></html>
"@
$destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ($destination -eq $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvPath)) { throw 'Output must not overwrite input CSV.' }
$parent = Split-Path -Parent $destination
if (-not (Test-Path -LiteralPath $parent)) { throw "Output folder does not exist: $parent" }
$html | Set-Content -LiteralPath $destination -Encoding UTF8
Write-Output "Events imported: $importedCount"
Write-Output "Unique events: $($records.Count)"
Write-Output "Duplicates removed: $duplicatesRemoved"
Write-Output "Threshold alerts: $($alerts.Count)"
Write-Output "Report saved: $destination"
