$ErrorActionPreference = 'Stop'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('phishing-lab-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    Copy-Item (Join-Path $PSScriptRoot 'Extract-LabEmail.ps1') $temporary
    $scriptPath = Join-Path $temporary 'Extract-LabEmail.ps1'
    $samplePath = Join-Path $PSScriptRoot 'sample-phishing.eml'
    $result = & $scriptPath -SamplePath $samplePath
    $checks = [ordered]@{
        'Original sample hash matches' = ($result.SHA256 -eq 'A8B936DA03CF64F34DC185DD23DF89424BA6D372B0F3690EBF227B6E62565CEB')
        'Sender extracted' = ($result.From -eq '"IT Support" <support@helpdesk-example.invalid>')
        'Reply-To extracted' = ($result.ReplyTo -eq 'password-reset@external-example.invalid')
        'Subject extracted' = ($result.Subject -eq 'Urgent: Your account will be disabled')
        'Folded authentication header unfolded' = ($result.AuthenticationResults -eq 'training.example.invalid; spf=fail smtp.mailfrom=helpdesk-example.invalid; dkim=none; dmarc=fail header.from=helpdesk-example.invalid')
        'Exactly one expected URL' = (@($result.URLs).Count -eq 1 -and $result.URLs[0] -eq 'https://account-verification.invalid/login')
        'Authentication remains unverified' = ($result.AuthenticationVerified -ceq $false)
        'Verdict requires analyst review' = ($result.Verdict -eq 'Not assessed - analyst review required')
        'JSON roundtrip preserves hash and URL' = $false
        'Missing header/body separator rejected' = $false
    }
    $saved = Get-Content (Join-Path $temporary 'extracted-evidence.json') -Raw | ConvertFrom-Json
    $checks['JSON roundtrip preserves hash and URL'] = (
        $saved.SHA256 -eq $result.SHA256 -and
        @($saved.URLs).Count -eq 1 -and
        $saved.URLs[0] -eq $result.URLs[0]
    )
    $bad = Join-Path $temporary 'malformed.eml'
    Set-Content $bad 'Subject: No body separator' -Encoding UTF8
    try {
        & $scriptPath -SamplePath $bad | Out-Null
    } catch {
        $checks['Missing header/body separator rejected'] = (
            $_.Exception.Message -like '*Missing blank line between headers and body*'
        )
    }
    $failed = 0
    foreach ($check in $checks.GetEnumerator()) {
        if ($check.Value) { Write-Output "PASS: $($check.Key)" }
        else { $failed++; Write-Output "FAIL: $($check.Key)" }
    }
    Write-Output "$($checks.Count - $failed)/$($checks.Count) tests passed"
    if ($failed -gt 0) { throw "$failed phishing extractor test(s) failed" }
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
