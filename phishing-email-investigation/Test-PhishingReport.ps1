$ErrorActionPreference = 'Stop'
$folder = Join-Path ([IO.Path]::GetTempPath()) ('phishing-report-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $folder | Out-Null
try {
    $evidence = Get-Content (Join-Path $PSScriptRoot 'extracted-evidence.json') -Raw | ConvertFrom-Json
    $evidence.Subject = '<script>alert("test")</script>'
    $evidencePath = Join-Path $folder 'evidence.json'
    $evidence | ConvertTo-Json -Depth 3 | Set-Content $evidencePath -Encoding UTF8
    $outputPath = Join-Path $folder 'report.html'
    & (Join-Path $PSScriptRoot 'New-PhishingReport.ps1') -EvidencePath $evidencePath -AnalysisPath (Join-Path $PSScriptRoot 'analysis.json') -OutputPath $outputPath
    $html = Get-Content $outputPath -Raw
    if ($html -notmatch '&lt;script&gt;' -or $html -match '<script>') { throw 'HTML encoding check failed' }
    if ($html -match '(?i)<a\s') { throw 'Unexpected clickable anchor' }
    if ($html -notmatch $evidence.SHA256 -or $html -notmatch 'support@helpdesk-example.invalid') { throw 'Evidence fields missing' }
    if ($html -notmatch 'Credential-phishing training scenario') { throw 'Analyst verdict missing' }
    Write-Output 'PASS: Report generated, evidence present, input encoded, and URLs not linked'
} finally {
    Remove-Item -LiteralPath $folder -Recurse -Force
}
