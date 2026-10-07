# H4wkEye 🦅

**Offline PAN-OS Configuration Security Scanner**

H4wkEye performs static security assessment of PAN-OS XML configuration exports without sending the configuration or report data over the network.

## Privacy model

- No telemetry, analytics, cloud APIs, DNS lookups, update checks, remote JavaScript/CSS, or other network functionality.
- Credential-bearing XML values are redacted in memory immediately after parsing and before discovery/report generation.
- `--privacy standard` keeps operational identifiers such as rule/object names and IP addresses in the local report.
- `--privacy strict` pseudonymizes common operational identifiers while preserving relationships for review.
- Generated reports are created with restrictive permissions (`0600`) where supported.

> Treat PAN-OS configuration exports and generated reports as sensitive security material.

## Usage

```bash
python3 h4wkeye.py firewall.xml --baseline baseline.json --output ./reports
python3 h4wkeye.py firewall.xml --baseline baseline.json --privacy strict --output ./reports-safe
```

## Supported assessment areas

Security rules, NAT/decryption discovery, site-to-site VPN correlation and crypto posture, GlobalProtect review, management plane checks, authentication/password profile review, network protection, address/group resolution, and configuration inventory.

## Important limitation

H4wkEye is a static configuration assessment tool. It does not prove live exploitability, reachability, negotiated VPN state, external IdP/MFA behavior, dynamic address-group runtime membership, or business justification. Findings require assessor validation.

## License

Apache License 2.0.


## PDF reports

H4wkEye generates HTML, PDF, CSV, and JSON reports from the same privacy-sanitized scan data.

Install the PDF dependency:

```bash
python3 -m pip install -r requirements.txt
```

The PDF is generated fully offline and embeds the local H4wkEye logo. Secret values are redacted before analysis, and `--privacy strict` pseudonymization is applied before PDF generation.
