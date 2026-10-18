# Changelog

All changes below describe the development lineage and should not be interpreted as full PAN-OS version certification.

## 3.0.10: Standalone coverage diagnostics and combined CSV reporting
- Add optional batch-only `--combined-csv` output, independent of individual `--format` selections.
- Consolidated findings include privacy-safe configuration identification and scan status; failed scans remain in `batch-summary.json`.
- Document combined reporting and add synthetic batch regression tests.
- Add privacy-safe structural entry counts for local rules and selected network, VPN, authentication and logging paths.
- Separate `NO_LOCAL_RULES` from `NOT_DETERMINED` effective-policy status; no inventory-only findings.
- Report zero-byte input as `EMPTY_FILE`.
- Fix contradictory partial-coverage notes when configuration-level findings exist.
- Warn on redaction-like XML element names without teaching the scanner nonstandard tag aliases.
- Retain `--format` selection and the existing Panorama reference/provenance diagnostics.

## Unreleased: optional report format update (based on v3.0.9)

### Added
- `--format` / `--formats` accepts `pdf`, `html`, `csv`, `json`, `all`, and comma-separated combinations.
- Batch summary records `requested_formats` and `generated_formats` for successful scans.
- `pdf_status: NOT_REQUESTED` when PDF output is not selected.
- Help and README documentation for `--max-xml-mib` (100 MiB default, 1–2048 MiB range).

### Changed
- Only requested main report renderers execute. Coverage diagnostics remain generated independently.
- PDF is optional, so ReportLab is only required when PDF is selected.

## 3.0.9: Policy provenance and layer normalization
- Preserve pre-rulebase/post-rulebase layer provenance, parser order, and per-scope layer diagnostics.
- Add `layer_accounting_valid` and rule layer breakdowns.
- Hotfix: correct misplaced `elem` reference that caused a `NameError` during discovery.
- Enterprise Panorama validation: 45,374 policy entries classified; 725 findings retained in that test export. These counts are **test data**, not scanner defaults.

## 3.0.8: Normalized diagnostic inventory
- Add privacy-safe scope, policy and object inventory for standalone/Panorama configuration models.
- Diagnostic only; not yet an effective-policy engine.

## 3.0.7: Generic reference audit accounting
- Reconcile nested reference visits across policy types and outcome categories.
- Add synthetic regression tests and standalone VSYS lookup support.

## 3.0.6: Reference audit
- Audit policy source, destination and service references, including nested groups, cycles and unresolved values.
- Keep reference diagnostics separate from security findings.

## 3.0.5: Scope-aware address lookup
- Prefer exact policy scope and then shared scope, without unrelated device-group fallback.
- Add address lookup counters.

## 3.0.4: Privacy-safe scope diagnostics
- Introduce pseudonymous identifiers, scope matching and identity quality metrics.

## 3.0.3: Panorama coverage diagnostics
- Compare XML policy counts to scanner-discovered counts; inventory device groups, templates and stacks.

## 3.0.2: Batch/report reliability
- Add batch XML scanning, configurable XML size limit, clearer errors and PDF overflow handling.
- Preserve scan results if PDF rendering fails.

## 3.0.1 and earlier
- Initial offline PAN-OS security configuration scanning, privacy modes and HTML/PDF/CSV/JSON reporting.
