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

## Hosted automated validation
On 18 October 2026, the Windows extractor-tests job completed successfully in [GitHub Actions run 39115587909](https://github.com/Banoth281/soc-login-lab/actions/runs/39115587909), testing commit 7ac234ca37edce1288a73e35fa1b5a454ef8a218. The suite executes ten assertions covering exact hash and extracted values, folded headers, JSON roundtrip, analyst-review status, and missing-separator rejection. This hosted run supplements the earlier three user-executed assertions. It validates the synthetic fixture, not a live email investigation or general MIME support.

## HTML report validation
The report generator and its encoding checks passed on Windows in [run 39115864024](https://github.com/Banoth281/soc-login-lab/actions/runs/39115864024). The user subsequently supplied report content showing the matching sample hash, extracted fields, analyst verdict, fixture labels, limitations, and generated UTC time 2026-10-18 09:35:14Z. This confirms content generation; visual browser layout has not been reviewed from a screenshot.
