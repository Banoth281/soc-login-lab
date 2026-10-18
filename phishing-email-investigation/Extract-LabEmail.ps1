param(
    [string]$SamplePath = (Join-Path $PSScriptRoot 'sample-phishing.eml')
)

$ErrorActionPreference = 'Stop'
$raw = Get-Content -LiteralPath $SamplePath -Raw
$parts = $raw -split '\r?\n\r?\n', 2

if ($parts.Count -ne 2) {
    throw 'Missing blank line between headers and body.'
}

$headers = $parts[0] -replace '\r?\n[ \t]+', ' '

function Read-Header {
    param([string]$Name)
    $pattern = '(?im)^' + [regex]::Escape($Name) + ':[ \t]*(.*)$'
    $match = [regex]::Match($headers, $pattern)
    if ($match.Success) {
        $match.Groups[1].Value.Trim()
    }
}

$urls = @(
    [regex]::Matches($parts[1], 'https?://[^\s<>"'']+') |
        ForEach-Object { $_.Value } |
        Sort-Object -Unique
)

$result = [pscustomobject]@{
    SHA256 = (Get-FileHash -LiteralPath $SamplePath).Hash
    From = Read-Header 'From'
    ReplyTo = Read-Header 'Reply-To'
    Subject = Read-Header 'Subject'
    AuthenticationResults = Read-Header 'Authentication-Results'
    AuthenticationVerified = $false
    URLs = @($urls)
    Verdict = 'Not assessed - analyst review required'
    NetworkRequestsMade = $false
}

$output = Join-Path $PSScriptRoot 'extracted-evidence.json'
$result | ConvertTo-Json -Depth 3 |
    Set-Content -LiteralPath $output -Encoding UTF8

$result
