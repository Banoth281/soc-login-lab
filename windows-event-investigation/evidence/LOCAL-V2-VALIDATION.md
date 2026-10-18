# Local Windows v2 validation
**Date:** 18 October 2026  
**Evidence source:** user-supplied PowerShell console output and confirmation. Original CSV, HTML, and manifest remain local and have not been uploaded.

## Results
| Check | Observed outcome |
|---|---|
| Original v2 suite | 30/30 synthetic tests passed locally |
| Actual Windows collection | 2 records, 2 unique events, 0 alerts |
| Context | Computer and domain populated; published identifiers omitted |
| Corrected HTML generator | 2 imported, 2 unique, 0 duplicates removed, 0 alerts |
| Output location | Report saved under the user's SOC-Lab-v2 folder |
| Report opening | User confirmed completion after the open instruction; no screenshot reviewed |
| Integrity manifest | CSV and HTML SHA-256 hashes saved and checked |
| Hash verification | Both local files matched their recorded hashes |

The 31st regression case covers the report path fix and passed on hosted Windows CI. A local run of all 31 tests was not supplied; the local synthetic result remains 30/30.

## File hashes reported by the user
| File | SHA-256 |
|---|---|
| lab-failed-logons-v2.csv | 4FF969744A6EEF594783BF386E9210AEE4D76F226F71B114FE6435354C59F572 |
| investigation-report-v2.html | 0B7701A3DDA72F3B038BAE268F79F2ECE4E19DD8BD11D64F1AE71125EEF7F6F3 |

Console verification:
```text
PASS: lab-failed-logons-v2.csv matches its recorded hash.
PASS: investigation-report-v2.html matches its recorded hash.
```

Hashes were calculated and verified on the user's computer. They have not been independently recomputed from uploaded v2 artifacts. Hashes support change detection, not independent proof of origin. Regenerating the HTML changes its generation time and hash.

## Report-path issue
The initial generator resolved relative output using the process directory and wrote to System32. It was corrected to use PowerShell provider path resolution. The updated script saved the report in the requested SOC-Lab-v2 folder. The fix also protects relative input/output path comparisons.

## Hosted regression evidence
[31/31 Windows regression cases passed](https://github.com/Banoth281/soc-login-lab/actions/runs/39119036887), including relative-path report generation.

## Scope
This validates an authorised local failed-logon collection and below-threshold detector result. It does not establish a live above-threshold attack, production deployment, or containment. Raw Windows machine/account context remains in local artifacts and should be reviewed before sharing.
