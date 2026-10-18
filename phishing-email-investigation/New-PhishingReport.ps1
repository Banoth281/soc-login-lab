param(
    [string]$EvidencePath = (Join-Path $PSScriptRoot 'extracted-evidence.json'),
    [string]$AnalysisPath = (Join-Path $PSScriptRoot 'analysis.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'phishing-report.html')
)
$ErrorActionPreference = 'Stop'
$evidence = Get-Content -LiteralPath $EvidencePath -Raw | ConvertFrom-Json
$analysis = Get-Content -LiteralPath $AnalysisPath -Raw | ConvertFrom-Json
if ($evidence.SHA256 -notmatch '^[a-fA-F0-9]{64}$' -or
    $analysis.SHA256 -ne $evidence.SHA256) {
    throw 'Evidence and analyst records must contain the same valid SHA-256.'
}
$destination = [IO.Path]::GetFullPath($OutputPath)
foreach ($inputFile in @($EvidencePath, $AnalysisPath)) {
    if ($destination -eq [IO.Path]::GetFullPath($inputFile)) {
        throw 'Output must not overwrite an input JSON file.'
    }
}
function Encode-Text {
    param($Value)
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}
$fields = [ordered]@{
    'SHA-256' = $evidence.SHA256
    'From' = $evidence.From
    'Reply-To' = $evidence.ReplyTo
    'Subject' = $evidence.Subject
    'Authentication header - unverified' = $evidence.AuthenticationResults
}
$rows = $fields.GetEnumerator() | ForEach-Object {
    '<tr><th>' + (Encode-Text $_.Key) + '</th><td>' + (Encode-Text $_.Value) + '</td></tr>'
}
$urlItems = @($evidence.URLs | ForEach-Object {
    '<li><code>' + (Encode-Text $_) + '</code></li>'
})
if ($urlItems.Count -eq 0) { $urlItems = @('<li>No URLs recorded.</li>') }
$verdict = Encode-Text $analysis.Verdict
$reason = Encode-Text $analysis.Reason
$generated = [datetime]::UtcNow.ToString('u')
$html = @"
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Phishing Email Investigation - Synthetic Lab</title>
<style>
body{margin:0;padding:32px;background:#eef3f8;color:#17283c;font:16px/1.6 system-ui,sans-serif}
main{max-width:1050px;margin:auto;background:#fff;border-radius:12px;padding:32px}
h1,h2{color:#12345a}.notice{padding:16px;background:#e9f5f4;border-left:4px solid #087e8b}
table{width:100%;border-collapse:collapse}th,td{padding:12px;border:1px solid #dae3ed;text-align:left;vertical-align:top}
th{width:24%;background:#f3f6fa}td,code{overflow-wrap:anywhere}code{font-size:14px}
small{color:#526176}@media(max-width:600px){body{padding:12px}main{padding:16px}}
@media print{body{padding:0;background:#fff}main{padding:0}}
</style></head>
<body><main>
<h1>Phishing Email Investigation</h1>
<p>Santhosh Banoth | Offline training case</p>
<div class="notice"><strong>Synthetic email - analyst-reviewed scenario.</strong><br>
No real email delivery, live reputation check, or containment action is demonstrated.
Authentication results are fixture text, not independently verified results.</div>
<h2>Extracted evidence</h2><table><tbody>$($rows -join '')</tbody></table>
<h2>Extracted URLs</h2><p>Displayed as text, not clickable links.</p><ul>$($urlItems -join '')</ul>
<h2>Analyst assessment</h2><p><strong>$verdict</strong></p><p>$reason</p>
<p>This assessment comes from analysis.json; the extractor does not automatically classify emails.</p>
<h2>Documented observations for this fixture</h2>
<ul><li>An explicit request to disclose a username and password.</li>
<li>A 30-minute deadline and threat of account disablement.</li>
<li>Different sender, reply destination, and verification-link domains.</li></ul>
<p>Domain differences alone do not establish malicious intent. These observations describe this training fixture and are not automatically inferred for other inputs.</p>
<h2>Proposed response</h2>
<ol><li>Preserve the original message and headers.</li><li>Verify the request through a known support channel.</li>
<li>Search authorised mail telemetry for other recipients.</li><li>Assess whether links were opened or credentials disclosed.</li>
<li>If exposure is confirmed, follow account-containment procedures.</li></ol>
<p>These are recommendations for a real incident; they were not performed in this lab.</p>
<h2>Evidence limits</h2>
<p>Simple plain-text fixture only. No MIME attachment analysis, URL reputation checking, delivery tracing, or independent SPF/DKIM/DMARC validation.
Matching JSON hashes associate the two supplied records; this report generator does not recalculate the original email hash.</p>
<small>Generated UTC: $generated | No external assets or scripts</small>
</main></body></html>
"@
Set-Content -LiteralPath $destination -Value $html -Encoding UTF8
Write-Output "Report saved: $destination"
