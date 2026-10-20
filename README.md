# H4wkEye

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

# Disable report finding consolidation when one row/card per original detection is preferred
python3 h4wkeye.py firewall.xml --no-group-findings --format all
```

### `--format` / `--formats`

Accepts `pdf`, `html`, `csv`, `json`, `all`, or comma-separated combinations such as `pdf,csv`. Format names are case-insensitive. `all` is the default and cannot be combined with other values. Invalid formats cause a command-line error. The selected formats control the **main findings reports**; `H4wkEye-coverage.json` is always generated, and batch mode also writes `batch-summary.json`. If PDF is not requested, ReportLab is not needed for that scan. A requested PDF failure is recorded without discarding successfully generated reports.

### `--max-xml-mib`

Maximum accepted XML input size, in **MiB** (1 MiB = 1,048,576 bytes). Default **100 MiB**; permitted range **1–2048 MiB**. Example: `--max-xml-mib 500` allows XML files up to 500 MiB. This is a safety input-size limit, **not a memory allocation or guarantee of successful scanning**. Large XML files can consume significantly more RAM than their on-disk size. Raise this only for trusted configuration exports on appropriately resourced systems.

## Outputs

For a single XML input, reports are written under `--output`. For batch input, each configuration gets a numbered folder beneath a timestamped batch directory. Depending on selected formats, output includes `H4wkEye-report.pdf`, `.html`, `.csv`, and/or `.json`. CSV format creates a grouped `H4wkEye-report.csv` summary and `H4wkEye-evidence.csv` with one row per original detection. `H4wkEye-coverage.json` is always produced. Batch runs also produce `batch-summary.json`, including requested/generated format metadata and PDF status (`GENERATED`, `FAILED`, or `NOT_REQUESTED`).

### Preview 8: consolidated findings and complete evidence

By default, compatible rule-level detections in Firewall Rules, NAT Rules and Decryption Rules are grouped into concise findings when their detection meaning, severity, confidence, status, scope, description, remediation and risk score match. Each group's affected-rule evidence retains individual rule/object names, scope, source/destination zones and object/IP values, applications, services, status, confidence and evidence. Non-rule findings remain separate to avoid merging unrelated VPN, management-plane or platform issues. This is report-layer consolidation; the underlying detection logic is unchanged.

- **PDF:** Landscape layout; each grouped finding is fully expanded, with a complete affected-rule table and repeating headers. No expand/collapse controls or hidden technical evidence. Large evidence sets continue across pages.
- **HTML:** Grouped finding cards with the complete per-rule technical evidence available in the technical-context section.
- **CSV:** `H4wkEye-report.csv` is the consolidated summary; `H4wkEye-evidence.csv` preserves one row per original detection.
- **JSON:** `findings` contains consolidated groups with nested `affected_rules` and original finding IDs.
- **Un-grouped view:** pass `--no-group-findings` to preserve one report entry per original detection.
- **Batch mode:** `combined-findings.csv` contains grouped summaries; `combined-evidence.csv` contains per-detection evidence rows.

Grouping does not mean that every rule is exploitable or effective. It reduces repeated prose while preserving the technical details for assessor review.

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

Use `--combined-csv` with `--input-dir` to generate `combined-findings.csv` (grouped summary) and `combined-evidence.csv` (one row per original detection) in the timestamped batch folder. Both include `configuration` and `scan_status` columns. In `--privacy strict` mode, the configuration column uses a pseudonym rather than the original filename. Failed inputs contribute no findings; consult `batch-summary.json` for failures and coverage limitations. Empty outputs retain header rows.

```bash
# Individual HTML reports plus a single combined findings CSV
python3 h4wkeye.py --input-dir ./PA-Configs --output-dir ./reports --format html --combined-csv

# Individual CSV reports and a consolidated CSV
python3 h4wkeye.py --input-dir ./PA-Configs --output-dir ./reports --format csv --combined-csv

# All four individual formats plus a consolidated CSV
python3 h4wkeye.py --input-dir ./PA-Configs --output-dir ./reports --combined-csv
```

`--combined-csv` is optional and batch-only. It does not alter `--format` selections or replace `batch-summary.json` and coverage diagnostics. It combines **findings**, not complete HTML/PDF reports or per-device policy simulations. Treat the consolidated file as confidential assessment data.

## v3.1.0 preview: Panorama inheritance diagnostics

The coverage JSON now includes `panorama_inheritance_preview`, a privacy-safe, count-only
device-group ancestry and policy-layer composition diagnostic. It lists shared pre-rules,
ancestor-to-child pre-rules, child-to-ancestor post-rules and shared post-rules.
This is **not** effective per-device policy: targets, local overrides, templates,
rule enablement, and runtime state remain unresolved. No new vulnerability findings
are generated from these counts. Missing parents, duplicate names and cycles are
reported as limitations. Do not publish this preview as a validated stable release.

## Preview 2: target diagnostics

The coverage JSON includes `panorama_targeting_preview` with raw-rule counts by
explicit target structure and enablement. This is **not** effective per-device
applicability. Device targeting, serial/vsys membership and runtime overrides
are not resolved. Findings are intentionally unchanged.

### Preview 3 targeting diagnostics

The `panorama_targeting_preview` coverage section classifies a missing target,
empty target, or `<target><negate>no</negate></target>` as
`NO_EXPLICIT_TARGET`. Explicit device entries are categorized as inclusion or
exclusion based on `negate`; malformed or ambiguous structures remain
`UNKNOWN_TARGET_SHAPE`. These categories describe XML targeting structure,
**not effective firewall policy applicability**. No device serial numbers or
rule names are exported by the targeting preview.

Expected targeting distribution for the previously inspected 45,374-rule
Panorama snapshot: `NO_EXPLICIT_TARGET: 45374`, unknown: 0. This is a
Kali-side acceptance target, not a full-snapshot test performed in this package.

Run `python3 test_v310_preview3.py` to check the classifier.

### Preview 4: device-group membership diagnostics
The coverage JSON now includes `panorama_membership_preview`. It reports aggregate assigned-device and VSYS assignment counts without exporting serial numbers or VSYS names. Multiple-group assignments and malformed VSYS structures are flagged. This is diagnostic-only and does not prove per-firewall policy applicability.


### Preview 5: VSYS-aware candidate mapping
The coverage JSON includes `panorama_candidate_mapping_preview`, with privacy-safe assignment IDs, ordered shared/ancestor/child policy sources and candidate/disabled/target counts. These are **not** deployed or effective policy counts. `DEVICE_ONLY` is not automatically interpreted as `vsys1`.


### Preview 6: candidate applicability diagnostics

Panorama coverage JSON includes `panorama_applicability_preview`, with per-assignment and aggregate counts for candidate rules, enablement, target eligibility, unresolved targeting and unique referenced XML source occurrences. `configuration_eligible_candidate` is **not** proof of deployment or enforcement. The diagnostic does not modify findings.

Inspect: `jq '.panorama_applicability_preview | {status, assignment_count, issues, unique_policy_source_occurrences_referenced, candidate_policy_references, by_type, effective_device_applicability}' H4wkEye-coverage.json`


### Preview 7 reconciliation diagnostics
Coverage JSON now includes `panorama_reconciliation_preview`, with source-to-candidate consistency, targeting coverage, and enablement/eligibility partitions. The values are assignment-level references, not deployed policies. Check `issues` and `status` before interpreting results.

### Preview 8: consolidated reporting

Preview 8 groups compatible findings in reports while retaining complete rule-level evidence. PDF evidence is always fully expanded and includes all affected rule rows, including IP/object context, without collapsible sections. CSV emits a summary (`H4wkEye-report.csv`) and detail evidence (`H4wkEye-evidence.csv`); batch `--combined-csv` emits `combined-findings.csv` and `combined-evidence.csv`. JSON stores nested `affected_rules`. Use `--no-group-findings` to preserve one report finding per detection.

Grouping does not change detection logic. It groups only findings with matching section, title, severity, confidence, status, description, remediation and risk score. All original per-rule evidence is retained.
