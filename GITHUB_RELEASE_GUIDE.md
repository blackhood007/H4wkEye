# H4wkEye v3.1.0 Preview 8: GitHub publication guide

This is a preview release, not a confirmed stable release. Keep the existing v3.0.10 tag intact.

## Release highlights
- Panorama hierarchy, device-group/VSYS assignment, targeting, enablement and policy-reference diagnostics (Previews 1-7).
- Privacy-safe policy reconciliation and explicit `NOT_EVALUATED` effective applicability.
- Consolidated rule-level findings for firewall, NAT and decryption policies.
- Complete affected-rule evidence in landscape PDF tables, including across page breaks; no hidden/collapsed sections.
- JSON `affected_rules`, summary CSV and detailed evidence CSV.
- `--no-group-findings` for ungrouped reporting.

## Real-world validation (user-provided)
- Raw policy occurrences: 45,374
- Candidate policy references: 95,663
- Reconciled device/VSYS assignments: 45/45
- Raw detections: 725
- Consolidated finding groups: 163
- Affected detections preserved by count: 725
- Findings with multiple affected rules: 60

These numbers describe one validation dataset, not universal scanner performance. Full PDF visual review and same-input findings parity are recommended before stable promotion.

## Publish to the existing repository from Kali

Run from a CLEAN clone of your repository, on a new preview branch:

```bash
git clone https://github.com/blackhood007/H4wkEye.git
cd H4wkEye
git switch -c feature/v3.1.0-preview8
# Extract the downloaded ZIP elsewhere, then copy its files into this repository root.
# Review changed files before staging:
git status --short
git diff -- README.md CHANGELOG.md h4wkeye.py
python3 h4wkeye.py --help
python3 -m py_compile h4wkeye.py
for t in test_*.py; do python3 "$t" || exit 1; done
git add h4wkeye.py README.md CHANGELOG.md CONTRIBUTING.md SECURITY.md test_*.py GITHUB_RELEASE_GUIDE.md
git commit -m "feat: Panorama diagnostics and consolidated evidence reporting (v3.1.0 preview 8)"
git push -u origin feature/v3.1.0-preview8
```

Create a pull request from `feature/v3.1.0-preview8` into the repository default branch. After review, merge the PR. Publish a prerelease tag (for example `v3.1.0-preview8`) only after tests and report checks pass. Do not overwrite the v3.0.10 tag.

**Privacy:** Never commit real customer XML, report output, serials, IP addresses, secrets, or test snapshots. Only synthetic test fixtures belong in the repository.

## CLI help and examples

```bash
python3 h4wkeye.py --help
python3 h4wkeye.py config.xml --format all
python3 h4wkeye.py config.xml --format pdf,csv
python3 h4wkeye.py config.xml --no-group-findings
python3 h4wkeye.py --input-dir ./configs --output-dir ./reports --max-xml-mib 500 --format all --combined-csv
python3 h4wkeye.py --input-dir ./configs --output-dir ./reports --recursive --privacy strict --format json,csv
```

| Option | Purpose |
| --- | --- |
| `xml` | Single XML configuration path |
| `--input-dir DIR` | Batch scan XML configurations in a directory |
| `--output`, `--output-dir PATH` | Report destination |
| `--baseline FILE` | Optional JSON baseline override |
| `--privacy standard\|strict` | Reporting privacy level |
| `--max-xml-mib N` | XML size limit, default 100 MiB; maximum 2048 |
| `--format`, `--formats` | `all`, `pdf`, `html`, `csv`, `json` or comma-separated selections |
| `--no-group-findings` | Disable default report finding consolidation |
| `--combined-csv` | Batch-only combined findings CSV, independent of selected report formats; Preview 8 also emits detailed combined evidence CSV |
| `--recursive` | Include subdirectories during batch scan |
| `-h`, `--help` | Display command-line help |

The scanner remains offline and does not establish actual deployed policy enforcement.