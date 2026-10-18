# H4wkEye 🦅

**Offline PAN-OS / Panorama XML Configuration Security Scanner**

H4wkEye analyzes Palo Alto Networks configuration XML locally, without uploading configurations to external services. It supports standalone firewall and Panorama discovery, security configuration checks, and coverage diagnostics. **This is a static assessment, not an effective per-firewall policy simulation.**

## Requirements

- Python 3; install dependencies from `requirements.txt` for PDF output.
- For Kali Linux, `sudo apt install python3-reportlab` may be preferable to system-wide `pip` installation.
- Sufficient RAM and disk space for large exports; XML size limit and memory requirements are different.

```bash
python3 -m pip install -r requirements.txt
python3 h4wkeye.py --help
```

## Usage

```bash
# Single firewall: all four report formats (default)
python3 h4wkeye.py firewall.xml --output ./reports

# Only PDF; does not require generating HTML, CSV or report JSON
python3 h4wkeye.py firewall.xml --output ./reports --format pdf

# Only CSV or HTML
python3 h4wkeye.py firewall.xml --output ./reports --format csv
python3 h4wkeye.py firewall.xml --output ./reports --format html

# Multiple selected formats
python3 h4wkeye.py firewall.xml --output ./reports --format pdf,csv

# All formats, explicitly
python3 h4wkeye.py firewall.xml --output ./reports --format all

# Batch scan; larger XML limit (500 MiB)
python3 h4wkeye.py --input-dir ./PA-Configs --output-dir ./reports --max-xml-mib 500 --format html,pdf

# Include XML files in subdirectories
python3 h4wkeye.py --input-dir ./PA-Configs --recursive --output-dir ./reports --format json

# Privacy and baseline options
python3 h4wkeye.py firewall.xml --privacy strict --baseline baseline.json --format pdf
```

### `--format` / `--formats`

Accepts `pdf`, `html`, `csv`, `json`, `all`, or comma-separated combinations such as `pdf,csv`. Format names are case-insensitive. `all` is the default and cannot be combined with other values. Invalid formats cause a command-line error. The selected formats control the **main findings reports**; `H4wkEye-coverage.json` is always generated, and batch mode also writes `batch-summary.json`. If PDF is not requested, ReportLab is not needed for that scan. A requested PDF failure is recorded without discarding successfully generated reports.

### `--max-xml-mib`

Maximum accepted XML input size, in **MiB** (1 MiB = 1,048,576 bytes). Default **100 MiB**; permitted range **1–2048 MiB**. Example: `--max-xml-mib 500` allows XML files up to 500 MiB. This is a safety input-size limit, **not a memory allocation or guarantee of successful scanning**. Large XML files can consume significantly more RAM than their on-disk size. Raise this only for trusted configuration exports on appropriately resourced systems.

## Outputs

For a single XML input, reports are written under `--output`. For batch input, each configuration gets a numbered folder beneath a timestamped batch directory. Depending on selected formats, output includes `H4wkEye-report.pdf`, `.html`, `.csv`, and/or `.json`. `H4wkEye-coverage.json` is always produced. Batch runs also produce `batch-summary.json`, including requested/generated format metadata and PDF status (`GENERATED`, `FAILED`, or `NOT_REQUESTED`).

## Assessment coverage and limitations

Current development builds include security rule checks, NAT and decryption discovery, site-to-site VPN and GlobalProtect checks, management plane, authentication, logging/network protection, and address/service reference diagnostics. Panorama diagnostics inventory device groups, shared objects, templates, template stacks, and pre/post-rulebase policy provenance. Scope-aware lookups avoid unrelated device-group fallback, and reference accounting is tracked separately from vulnerability findings.

**Important:** Panorama device-group inheritance, template overlays, firewall-local overrides, and effective per-device policy are **not fully resolved**. Panorama runs may correctly show `PARTIAL`. A finding is not proof of exploitability or business impact. Static exports cannot establish live reachability, dynamic address-group membership, negotiated VPN state, or external MFA/IdP enforcement. Unsupported or sanitized values can reduce assessment completeness. Validate contextual findings before reporting them as vulnerabilities.

## Privacy and security

No telemetry or network reporting is required. Sensitive values are redacted during scanning. `--privacy standard` retains some operational identifiers in local reports; `--privacy strict` pseudonymizes additional identifiers. Coverage diagnostics use generated scope identifiers, but **review every file before sharing**. Treat XML exports and generated reports as confidential security material. Generated report files use restrictive permissions where supported.

## Development and contribution

This package represents the **v3.0.9 policy-provenance engine with optional report formats**, a post-v3.0.9 development update. It is not yet a fully validated public v3.1.0 release. Test against synthetic standalone PAN-OS and Panorama configurations, as well as large exports, before publishing. Do not commit customer configurations, real credentials, or sensitive reports.

## License

Apache License 2.0. See `LICENSE`.

## v3.0.10 configuration coverage diagnostics

The scanner distinguishes actual policy entries from empty XML containers. For standalone exports, `H4wkEye-coverage.json` includes `configuration_coverage` with local policy counts, counts of known configuration paths, a `NO_LOCAL_RULES` marker, and `NOT_DETERMINED` effective-policy status. Counts are inventory only, **not vulnerability findings or proof of security assessment**. Panorama inheritance and pushed policy evaluation remain unsupported.

Zero-byte XML files fail with `EMPTY_FILE`. Structural element names containing redaction-like text are counted as warnings without exposing their values; sanitize values and identifiers, never XML tag names. Batch `PARTIAL` results should not be interpreted as clean bills of health.

### Combined findings CSV (batch mode)

Use `--combined-csv` with `--input-dir` to generate one additional `combined-findings.csv` in the timestamped batch folder. It contains all findings from successfully scanned XML files, with `configuration` and `scan_status` columns identifying the source of each row. The combined CSV uses the same finding columns and privacy transformations as individual CSV reports. In `--privacy strict` mode, the configuration column uses a pseudonym rather than the original filename. Failed inputs contribute no findings; consult `batch-summary.json` for failures and coverage limitations. If no findings are produced, the CSV still contains a header row.

```bash
# Individual HTML reports plus a single combined findings CSV
python3 h4wkeye.py --input-dir ./PA-Configs --output-dir ./reports --format html --combined-csv

# Individual CSV reports and a consolidated CSV
python3 h4wkeye.py --input-dir ./PA-Configs --output-dir ./reports --format csv --combined-csv

# All four individual formats plus a consolidated CSV
python3 h4wkeye.py --input-dir ./PA-Configs --output-dir ./reports --combined-csv
```

`--combined-csv` is optional and batch-only. It does not alter `--format` selections or replace `batch-summary.json` and coverage diagnostics. It combines **findings**, not complete HTML/PDF reports or per-device policy simulations. Treat the consolidated file as confidential assessment data.
