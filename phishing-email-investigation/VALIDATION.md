# Validation record
Date: 18 October 2026.

## User-executed checks
The user supplied console output showing successful reusable-script execution and these assertions:
```text
PASS: Sample hash matches
PASS: Reply-To extracted correctly
PASS: Exactly one expected URL
```
Expected values:
- SHA-256: A8B936DA03CF64F34DC185DD23DF89424BA6D372B0F3690EBF227B6E62565CEB
- Reply-To: password-reset@external-example.invalid
- URL count: 1
- URL: https://account-verification.invalid/login

## Independently checked uploaded artifacts
The five selected files exactly match corresponding entries in SOC-Phishing-Lab.zip. SHA-256 calculated from uploaded sample bytes matches the recorded value. Both JSON files parse and refer to the same sample. Extractor source contains local file reads, regular expressions, hashing, JSON output, and no network-request command.

The script was reviewed but not rerun in the authoring environment because PowerShell is unavailable. Windows execution evidence comes from the user's console transcript. No fabricated run or automated phishing CI success is claimed.

## Evidence handling
Original selected files are uploaded without byte changes. The broken .backup file and redundant ZIP are excluded. Git attributes protect the sample from line-ending conversion. No private email, account password, or live malicious URL is present in the selected synthetic fixture.
