#!/usr/bin/env python3
"""
H4wkEye v3.0.1
Standard-library-only, read-only XML configuration assessment.

Usage:
    python3 h4wkeye.py PA-config.xml
    python3 h4wkeye.py PA-config.xml --output ./reports
    python3 h4wkeye.py PA-config.xml --baseline baseline.json
"""

import argparse
import base64
import hashlib
import os
import secrets
import csv
import html
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

VERSION = "3.0.1"

DEFAULT_BASELINE = {
    "weak_encryption": ["des", "3des"],
    "weak_hash": ["md5", "sha1", "sha-1"],
    "weak_dh_groups": ["group1", "group2", "group5"],
    "rule_score": {
        "source_any": 2,
        "destination_any": 2,
        "from_any": 2,
        "to_any": 2,
        "application_any": 3,
        "service_any": 2,
        "missing_security_profile": 2,
        "missing_log_end": 1,
        "missing_log_forwarding": 1,
    },
    "rule_thresholds": {
        "critical": 12,
        "high": 9,
        "medium": 6,
        "low": 3,
    }
}

SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
}

SECTION_ORDER = [
    "Firewall Rules",
    "Decryption Rules",
    "NAT Rules",
    "Site-to-Site VPN",
    "GlobalProtect",
    "Management Plane",
    "Threat Prevention",
    "Logging & Monitoring",
    "Network Protection",
    "Authentication Security",
    "Manual Review",
]


def text_of(elem, path=None, default=""):
    if elem is None:
        return default
    target = elem.find(path) if path else elem
    if target is None or target.text is None:
        return default
    return target.text.strip()


def members(elem, path):
    if elem is None:
        return []
    return [
        m.text.strip()
        for m in elem.findall(path + "/member")
        if m.text and m.text.strip()
    ]


def yes(value):
    return str(value).strip().lower() == "yes"


def uniq(values):
    result = []
    seen = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def normalize_alg(value):
    return str(value or "").strip().lower().replace("_", "-")


def safe_join(values):
    if values is None:
        return ""
    if isinstance(values, (list, tuple, set)):
        return ", ".join(str(x) for x in values)
    return str(values)


MAX_XML_BYTES = 100 * 1024 * 1024
REDACTED = "[REDACTED]"
SENSITIVE_TAG_PARTS = (
    "password", "passwd", "passphrase", "pre-shared-key", "private-key",
    "secret", "community", "api-key", "auth-key", "authentication-key",
    "cookie-encryption", "shared-key", "bind-password",
)


def reject_unsafe_xml(path):
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_XML_BYTES:
        raise ValueError(f"XML file exceeds safety limit ({MAX_XML_BYTES // (1024*1024)} MiB)")
    with path.open("rb") as f:
        head = f.read(min(size, 2 * 1024 * 1024)).upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
        raise ValueError("DOCTYPE/ENTITY declarations are not accepted in offline scan input")


def redact_secret_nodes(root):
    """Irreversibly redact credential-bearing XML values before discovery/reporting."""
    redacted = 0
    for elem in root.iter():
        tag = str(elem.tag).lower().replace("_", "-")
        sensitive = any(part in tag for part in SENSITIVE_TAG_PARTS)
        if sensitive:
            # Keep structure/presence intact while removing values.
            if elem.text and elem.text.strip():
                elem.text = REDACTED
                redacted += 1
            for child in elem.iter():
                if child is not elem and child.text and child.text.strip():
                    child.text = REDACTED
                    redacted += 1
        for key in list(elem.attrib):
            k = key.lower().replace("_", "-")
            if any(part in k for part in SENSITIVE_TAG_PARTS):
                elem.attrib[key] = REDACTED
                redacted += 1
    return redacted


def _alias(value, kind, salt):
    if value in (None, "", [], {}, "any", "application-default", REDACTED):
        return value
    raw = str(value)
    digest = hashlib.sha256((salt + "|" + kind + "|" + raw).encode()).hexdigest()[:10]
    return f"{kind}-{digest}"


def apply_privacy(data, mode, salt):
    """Sanitize report data. Secrets are already redacted; strict mode pseudonymizes identifiers."""
    if mode != "strict":
        data["metadata"]["privacy_mode"] = mode
        return data

    sensitive_keys = {
        "configuration":"file", "object":"obj", "scope":"scope", "source_zones":"zone",
        "source_objects":"obj", "resolved_sources":"addr", "destination_zones":"zone",
        "destination_objects":"obj", "resolved_destinations":"addr", "peer_address":"addr",
        "local_interface":"if", "tunnel_interface":"if", "ike_gateway":"vpn",
        "ike_profile":"profile", "ipsec_profile":"profile", "tunnel":"vpn", "name":"obj",
    }

    def walk(obj, parent_key=""):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k in sensitive_keys:
                    kind = sensitive_keys[k]
                    if isinstance(v, list):
                        out[k] = [_alias(x, kind, salt) for x in v]
                    elif isinstance(v, dict):
                        out[k] = walk(v, k)
                    else:
                        out[k] = _alias(v, kind, salt)
                else:
                    out[k] = walk(v, k)
            return out
        if isinstance(obj, list):
            return [walk(x, parent_key) for x in obj]
        return obj

    clean = walk(data)
    clean["metadata"]["privacy_mode"] = "strict"
    clean["metadata"]["privacy_note"] = "Operational identifiers pseudonymized; credential values redacted before analysis."
    return clean


def load_logo_data_uri():
    candidates = [
        Path(__file__).resolve().parent / "assets" / "h4wk-logo.png",
        Path.cwd() / "assets" / "h4wk-logo.png",
    ]
    for logo in candidates:
        if logo.is_file():
            encoded = base64.b64encode(logo.read_bytes()).decode("ascii")
            return "data:image/png;base64," + encoded
    return ""


def chmod_private(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

class Scanner:
    def __init__(self, xml_path, baseline):
        self.xml_path = Path(xml_path)
        self.baseline = baseline
        reject_unsafe_xml(self.xml_path)
        self.tree = ET.parse(self.xml_path)
        self.root = self.tree.getroot()
        self.redacted_secret_values = redact_secret_nodes(self.root)

        self.parent = {
            child: parent
            for parent in self.root.iter()
            for child in parent
        }

        self.findings = []
        self.inventory = Counter()

        self.addresses = defaultdict(dict)
        self.address_groups = defaultdict(dict)

        self.security_rules = []
        self.decryption_rules = []
        self.nat_rules = []

        self.ike_profiles = {}
        self.ipsec_profiles = {}
        self.ike_gateways = {}
        self.ipsec_tunnels = []

        self.gp_portals = []
        self.gp_gateways = []

        self.mgmt_profiles = {}
        self.mgmt_profile_refs = []
        self.zone_protection_profiles = {}
        self.zone_protection_refs = []
        self.dos_profiles = {}
        self.auth_profiles = {}
        self.password_profiles = {}
        self.rule_statistics = Counter()

    # ----------------------------
    # Scope / ancestry
    # ----------------------------

    def ancestry(self, elem):
        chain = []
        cur = elem
        while cur is not None:
            chain.append(cur)
            cur = self.parent.get(cur)
        return list(reversed(chain))

    def scope(self, elem):
        chain = self.ancestry(elem)
        parts = []

        for i, node in enumerate(chain):
            if node.tag == "shared":
                parts.append("shared")

            if node.tag == "entry":
                p = self.parent.get(node)
                if p is None:
                    continue

                name = node.get("name", "")

                if p.tag == "devices":
                    parts.append(f"device:{name or 'unknown'}")
                elif p.tag == "vsys":
                    parts.append(f"vsys:{name or 'unknown'}")
                elif p.tag in ("device-group", "device-groups"):
                    parts.append(f"device-group:{name or 'unknown'}")
                elif p.tag in ("template", "templates"):
                    parts.append(f"template:{name or 'unknown'}")
                elif p.tag in ("template-stack", "template-stacks"):
                    parts.append(f"template-stack:{name or 'unknown'}")

        ptpl = elem.get("ptpl")
        if ptpl:
            parts.append(f"ptpl:{ptpl}")

        return " > ".join(uniq(parts)) or "device/local"

    def scope_key(self, elem):
        return self.scope(elem)

    # ----------------------------
    # Findings
    # ----------------------------

    def add_finding(
        self,
        severity,
        confidence,
        section,
        title,
        obj,
        description,
        evidence,
        remediation,
        *,
        status="UNKNOWN",
        scope="",
        source_zones=None,
        source_objects=None,
        resolved_sources=None,
        destination_zones=None,
        destination_objects=None,
        resolved_destinations=None,
        applications=None,
        services=None,
        risk_score=None,
    ):
        self.findings.append({
            "severity": severity,
            "confidence": confidence,
            "status": status,
            "section": section,
            "title": title,
            "object": obj or "",
            "scope": scope or "",
            "risk_score": "" if risk_score is None else risk_score,
            "source_zones": safe_join(source_zones),
            "source_objects": safe_join(source_objects),
            "resolved_sources": safe_join(resolved_sources),
            "destination_zones": safe_join(destination_zones),
            "destination_objects": safe_join(destination_objects),
            "resolved_destinations": safe_join(resolved_destinations),
            "applications": safe_join(applications),
            "services": safe_join(services),
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
        })

    # ----------------------------
    # Address discovery/resolution
    # ----------------------------

    def discover_addresses(self):
        for container in self.root.iter("address"):
            for entry in container.findall("./entry"):
                name = entry.get("name")
                if not name:
                    continue

                scope = self.scope_key(entry)
                value = None
                kind = "other"

                for tag in ("ip-netmask", "ip-range", "fqdn"):
                    val = text_of(entry, f"./{tag}")
                    if val:
                        value = val
                        kind = tag
                        break

                self.addresses[scope][name] = {
                    "name": name,
                    "scope": scope,
                    "type": kind,
                    "value": value or "",
                }
                self.inventory["Address objects"] += 1
                self.inventory[f"Address objects: {kind}"] += 1

        for container in self.root.iter("address-group"):
            for entry in container.findall("./entry"):
                name = entry.get("name")
                if not name:
                    continue

                scope = self.scope_key(entry)
                static = members(entry, "./static")
                dynamic_filter = text_of(entry, "./dynamic/filter")

                if static:
                    kind = "static"
                elif dynamic_filter:
                    kind = "dynamic"
                else:
                    kind = "other"

                self.address_groups[scope][name] = {
                    "name": name,
                    "scope": scope,
                    "type": kind,
                    "members": static,
                    "filter": dynamic_filter,
                }
                self.inventory["Address groups"] += 1
                self.inventory[f"Address groups: {kind}"] += 1

    def candidate_scopes(self, requested_scope):
        # Exact scope first, then progressively broader/fallback scopes.
        scopes = list(self.addresses.keys() | self.address_groups.keys())
        ordered = []

        if requested_scope:
            ordered.append(requested_scope)

            req_parts = requested_scope.split(" > ")
            for scope in scopes:
                if scope == requested_scope:
                    continue
                score = sum(1 for p in req_parts if p in scope)
                if score:
                    ordered.append((score, scope))

        ordered.extend((0, s) for s in scopes if s != requested_scope)

        normalized = []
        for item in ordered:
            if isinstance(item, tuple):
                normalized.append(item)
            else:
                normalized.append((999, item))

        normalized.sort(key=lambda x: (-x[0], x[1]))

        result = []
        for _, scope in normalized:
            if scope not in result:
                result.append(scope)
        return result

    def lookup_address(self, name, scope):
        exact = []
        for candidate in self.candidate_scopes(scope):
            if name in self.addresses.get(candidate, {}):
                exact.append(("address", candidate, self.addresses[candidate][name]))
            if name in self.address_groups.get(candidate, {}):
                exact.append(("group", candidate, self.address_groups[candidate][name]))

            # Exact scope wins immediately.
            if candidate == scope and exact:
                return exact[0], False

        if len(exact) == 1:
            return exact[0], False
        if len(exact) > 1:
            return exact[0], True
        return None, False

    def resolve_object(self, name, scope, stack=None):
        stack = stack or []

        if not name:
            return []

        if name.lower() == "any":
            return ["any"]

        # Literal IP/network/range-like values.
        try:
            ipaddress.ip_network(name, strict=False)
            return [name]
        except ValueError:
            pass

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}(?:\.\d{1,3}){3}", name):
            return [name]

        if name in stack:
            return [f"{name} [group-cycle]"]

        lookup, ambiguous = self.lookup_address(name, scope)
        if lookup is None:
            return [f"{name} [unresolved]"]

        kind, found_scope, obj = lookup
        suffix = " [ambiguous-scope]" if ambiguous else ""

        if kind == "address":
            if obj["type"] == "fqdn":
                return [f"FQDN:{obj['value']}{suffix}"]
            return [f"{obj['value']}{suffix}" if obj["value"] else f"{name} [unsupported]"]

        if obj["type"] == "dynamic":
            return [f"DYNAMIC({obj['filter']}){suffix}"]

        if obj["type"] != "static":
            return [f"{name} [unsupported-group]"]

        result = []
        for member in obj["members"]:
            result.extend(self.resolve_object(member, found_scope, stack + [name]))
        return uniq(result)

    def resolve_many(self, objects, scope):
        result = []
        for obj in objects:
            result.extend(self.resolve_object(obj, scope))
        return uniq(result)

    # ----------------------------
    # Policy discovery
    # ----------------------------

    def discover_policy(self):
        for elem in self.root.iter():
            if elem.tag not in {"security", "decryption", "nat"}:
                continue

            rules = elem.find("./rules")
            if rules is None:
                continue

            for entry in rules.findall("./entry"):
                name = entry.get("name", "")
                scope = self.scope(entry)

                common = {
                    "name": name,
                    "scope": scope,
                    "from": members(entry, "./from"),
                    "to": members(entry, "./to"),
                    "source": members(entry, "./source"),
                    "destination": members(entry, "./destination"),
                    "service": members(entry, "./service"),
                    "action": text_of(entry, "./action"),
                    "disabled": yes(text_of(entry, "./disabled")),
                    "description": text_of(entry, "./description"),
                    "tags": members(entry, "./tag"),
                    "log_setting": text_of(entry, "./log-setting"),
                }

                if elem.tag == "security":
                    common.update({
                        "application": members(entry, "./application"),
                        "source_user": members(entry, "./source-user"),
                        "source_hip": members(entry, "./source-hip"),
                        "destination_hip": members(entry, "./destination-hip"),
                        "log_start": text_of(entry, "./log-start"),
                        "log_end": text_of(entry, "./log-end"),
                        "rule_type": text_of(entry, "./rule-type"),
                        "profile_groups": members(entry, "./profile-setting/group"),
                        "profile_individual": {
                            child.tag: members(entry, f"./profile-setting/profiles/{child.tag}")
                            for child in entry.findall("./profile-setting/profiles/*")
                        },
                    })
                    self.security_rules.append(common)
                    self.inventory["Security rules"] += 1

                elif elem.tag == "decryption":
                    common.update({
                        "profile": text_of(entry, "./profile"),
                        "type_children": [c.tag for c in entry.findall("./type/*")],
                    })
                    self.decryption_rules.append(common)
                    self.inventory["Decryption rules"] += 1

                elif elem.tag == "nat":
                    common.update({
                        "source_translation": ET.tostring(
                            entry.find("./source-translation"), encoding="unicode"
                        ) if entry.find("./source-translation") is not None else "",
                        "destination_translation": ET.tostring(
                            entry.find("./destination-translation"), encoding="unicode"
                        ) if entry.find("./destination-translation") is not None else "",
                        "dynamic_destination_translation": ET.tostring(
                            entry.find("./dynamic-destination-translation"), encoding="unicode"
                        ) if entry.find("./dynamic-destination-translation") is not None else "",
                    })
                    self.nat_rules.append(common)
                    self.inventory["NAT rules"] += 1

    def security_profile_present(self, rule):
        if rule["profile_groups"]:
            return True
        return any(rule["profile_individual"].values())

    def rule_score_to_severity(self, score):
        t = self.baseline["rule_thresholds"]
        if score >= t["critical"]:
            return "CRITICAL"
        if score >= t["high"]:
            return "HIGH"
        if score >= t["medium"]:
            return "MEDIUM"
        if score >= t["low"]:
            return "LOW"
        return "INFO"

    def assess_security_rules(self):
        """
        Stabilized v2.2 firewall-rule assessment.

        Design goals:
        - Keep prevalence metrics separate from findings.
        - Never flag application=any by itself.
        - Treat explicit App-ID + application-default as a mitigating pattern.
        - App=any + Service=any alone is MEDIUM, not HIGH.
        - HIGH requires unrestricted app/service plus additional address/zone
          breadth, or multiple broad dimensions with weak compensating controls.
        - CRITICAL is intentionally not assigned from XML broadness alone because
          exposure/reachability and business context are required.
        """
        stats = self.rule_statistics

        for rule in self.security_rules:
            # Count every parsed security rule before any filtering.
            stats["Total security rules"] += 1

            if rule["disabled"]:
                stats["Disabled security rules"] += 1
                continue

            stats["Enabled security rules"] += 1

            action = rule["action"].lower()
            if action == "allow":
                stats["Enabled allow rules"] += 1
            else:
                stats["Enabled non-allow rules"] += 1
                continue

            source_any = "any" in rule["source"]
            destination_any = "any" in rule["destination"]
            from_any = "any" in rule["from"]
            to_any = "any" in rule["to"]
            application_any = "any" in rule["application"]
            service_any = ("any" in rule["service"]) or not rule["service"]
            application_default = "application-default" in rule["service"]
            no_profile = not self.security_profile_present(rule)
            no_log_end = rule["log_end"].lower() == "no"
            no_log_forwarding = not rule["log_setting"]

            # Broad statistics: these describe posture, not vulnerabilities.
            if source_any:
                stats["Allow rules: source any"] += 1
            if destination_any:
                stats["Allow rules: destination any"] += 1
            if from_any:
                stats["Allow rules: source zone any"] += 1
            if to_any:
                stats["Allow rules: destination zone any"] += 1
            if application_any:
                stats["Allow rules: application any"] += 1
            if service_any:
                stats["Allow rules: service any"] += 1
            if application_default:
                stats["Allow rules: application-default"] += 1
            if no_profile:
                stats["Allow rules: no security profile"] += 1
            if no_log_end:
                stats["Allow rules: log-end disabled"] += 1
            if no_log_forwarding:
                stats["Allow rules: no log forwarding profile"] += 1

            address_breadth = sum((source_any, destination_any))
            zone_breadth = sum((from_any, to_any))
            app_service_unrestricted = application_any and service_any

            indicators = []
            score = 0

            def add(points, label):
                nonlocal score
                score += points
                indicators.append(label)

            # Primary broadness conditions.
            if source_any and destination_any:
                add(4, "Source and destination are both any")

            if from_any and to_any:
                add(4, "Source and destination zones are both any")

            if app_service_unrestricted:
                add(4, "Application and service are both any")

            if destination_any and to_any:
                add(2, "Destination object and destination zone are both any")

            if source_any and from_any:
                add(2, "Source object and source zone are both any")

            # Cross-dimensional breadth adds pressure, but does not independently
            # manufacture a finding.
            if application_any and (address_breadth >= 1 or zone_breadth >= 1):
                add(1, "Application is any in a broadly scoped rule")

            if service_any and (address_breadth >= 1 or zone_breadth >= 1):
                add(1, "Service is any in a broadly scoped rule")

            broad_network_scope = address_breadth >= 1 or zone_breadth >= 1
            strongly_broad_network_scope = address_breadth >= 2 or zone_breadth >= 2

            # Compensating-control gaps matter only when meaningful breadth exists.
            if no_profile and (
                app_service_unrestricted or strongly_broad_network_scope
            ):
                add(2, "Broad allow rule has no detected Security Profile")

            if no_log_end and (
                app_service_unrestricted or strongly_broad_network_scope
            ):
                add(1, "Broad allow rule has session-end logging disabled")

            if no_log_forwarding and (
                app_service_unrestricted or strongly_broad_network_scope
            ):
                add(1, "Broad allow rule has no log forwarding profile")

            # Positive control: explicit App-ID + application-default is a
            # materially better pattern. It can remain in statistics/manual
            # review unless the network scope itself is exceptionally broad.
            explicit_app_default = application_default and not application_any
            if explicit_app_default:
                add(-1, "Mitigation: explicit App-ID uses application-default")

            # Determine whether this deserves an individual finding.
            # Single broad dimensions and low residual scores stay statistical.
            base_reportable = (
                app_service_unrestricted
                or (source_any and destination_any)
                or (from_any and to_any)
                or (
                    application_any
                    and (
                        address_breadth >= 2
                        or zone_breadth >= 2
                    )
                )
            )

            # Explicit App-ID + application-default with only one broad pair and
            # low residual risk is suppressed from the vulnerability table.
            if explicit_app_default and score <= 3:
                stats["Application-default broad observations suppressed"] += 1
                stats["Broad observations suppressed from findings"] += 1
                continue

            if not base_reportable:
                stats["Broad observations suppressed from findings"] += 1
                continue

            # Severity model:
            # MEDIUM: broad but limited combinations, including app:any+service:any.
            # HIGH: app/service unrestricted plus network breadth, or multiple
            # strongly broad dimensions / weak compensating controls.
            # CRITICAL is intentionally reserved for future reachability/exposure
            # validation rather than inferred solely from configuration breadth.
            high_risk = (
                (
                    app_service_unrestricted
                    and broad_network_scope
                )
                or (
                    strongly_broad_network_scope
                    and application_any
                    and (
                        service_any
                        or no_profile
                    )
                )
                or score >= 8
            )

            severity = "HIGH" if high_risk else "MEDIUM"
            stats[f"Reportable broad rules: {severity.lower()}"] += 1

            resolved_src = self.resolve_many(rule["source"], rule["scope"])
            resolved_dst = self.resolve_many(rule["destination"], rule["scope"])

            self.add_finding(
                severity,
                "REVIEW REQUIRED",
                "Firewall Rules",
                "Broad Allow Security Rule",
                rule["name"],
                "The enabled allow rule combines multiple broad matching criteria "
                "and/or lacks compensating security controls. A single 'any' value "
                "is not sufficient to create this finding.",
                "; ".join(indicators),
                "Validate the business requirement and narrow zones, addresses, "
                "applications and services where possible. Prefer explicit App-ID "
                "with application-default when appropriate, and attach approved "
                "Security Profiles and logging controls.",
                status="ACTIVE",
                scope=rule["scope"],
                source_zones=rule["from"],
                source_objects=rule["source"],
                resolved_sources=resolved_src,
                destination_zones=rule["to"],
                destination_objects=rule["destination"],
                resolved_destinations=resolved_dst,
                applications=rule["application"],
                services=rule["service"],
                risk_score=max(score, 0),
            )

    def assess_decryption_rules(self):
        for rule in self.decryption_rules:
            if rule["disabled"]:
                continue

            action = rule["action"].lower()
            broad = (
                "any" in rule["source"]
                and "any" in rule["destination"]
            )

            if action in {"no-decrypt", "no_decrypt"} and broad:
                self.add_finding(
                    "MEDIUM",
                    "REVIEW REQUIRED",
                    "Decryption Rules",
                    "Broad No-Decryption Rule",
                    rule["name"],
                    "A broad decryption exclusion was discovered. Legitimate exclusions exist, "
                    "but broad bypasses can reduce inspection visibility.",
                    f"source={rule['source']}; destination={rule['destination']}; action={rule['action']}",
                    "Confirm the exclusion is narrowly scoped and documented. Restrict source, "
                    "destination, category and service criteria where possible.",
                    status="ACTIVE",
                    scope=rule["scope"],
                    source_zones=rule["from"],
                    source_objects=rule["source"],
                    resolved_sources=self.resolve_many(rule["source"], rule["scope"]),
                    destination_zones=rule["to"],
                    destination_objects=rule["destination"],
                    resolved_destinations=self.resolve_many(rule["destination"], rule["scope"]),
                    services=rule["service"],
                )

    def assess_nat_rules(self):
        # NAT is mostly contextual. Inventory broad rules for manual review without
        # automatically claiming a vulnerability.
        for rule in self.nat_rules:
            if rule["disabled"]:
                continue

            if "any" in rule["source"] and "any" in rule["destination"]:
                self.add_finding(
                    "INFO",
                    "REVIEW REQUIRED",
                    "NAT Rules",
                    "Broad NAT Rule",
                    rule["name"],
                    "The NAT rule matches unrestricted source and destination objects. "
                    "This can be legitimate depending on routing and publication design.",
                    f"from={rule['from']}; to={rule['to']}; service={rule['service'] or ['any']}",
                    "Confirm the rule scope and translation behavior match the intended network design.",
                    status="ACTIVE",
                    scope=rule["scope"],
                    source_zones=rule["from"],
                    source_objects=rule["source"],
                    resolved_sources=self.resolve_many(rule["source"], rule["scope"]),
                    destination_zones=rule["to"],
                    destination_objects=rule["destination"],
                    resolved_destinations=self.resolve_many(rule["destination"], rule["scope"]),
                    services=rule["service"],
                )

    # ----------------------------
    # VPN
    # ----------------------------

    def discover_crypto_profiles(self):
        for elem in self.root.iter():
            if elem.tag == "ike-crypto-profiles":
                for entry in elem.findall("./entry"):
                    self._store_ike_profile(entry)
            elif elem.tag == "ipsec-crypto-profiles":
                for entry in elem.findall("./entry"):
                    self._store_ipsec_profile(entry)

        # Generic fallback for common PAN-OS structures.
        for entry in self.root.findall(".//network/ike/crypto-profiles/ike-crypto-profiles/entry"):
            self._store_ike_profile(entry)
        for entry in self.root.findall(".//network/ike/crypto-profiles/ipsec-crypto-profiles/entry"):
            self._store_ipsec_profile(entry)

        self.inventory["IKE crypto profiles"] = len(self.ike_profiles)
        self.inventory["IPsec crypto profiles"] = len(self.ipsec_profiles)

    def _profile_values(self, entry, tags):
        values = []
        for tag in tags:
            for elem in entry.iter(tag):
                if elem.text and elem.text.strip():
                    values.append(elem.text.strip())
                for m in elem.findall("./member"):
                    if m.text and m.text.strip():
                        values.append(m.text.strip())
        return uniq(values)

    def _store_ike_profile(self, entry):
        name = entry.get("name")
        if not name:
            return
        key = (self.scope(entry), name)
        self.ike_profiles[key] = {
            "name": name,
            "scope": self.scope(entry),
            "encryption": self._profile_values(entry, ["encryption"]),
            "authentication": self._profile_values(entry, ["hash", "authentication"]),
            "dh": self._profile_values(entry, ["dh-group"]),
            "lifetime": self._profile_values(entry, ["lifetime"]),
        }

    def _store_ipsec_profile(self, entry):
        name = entry.get("name")
        if not name:
            return
        key = (self.scope(entry), name)
        self.ipsec_profiles[key] = {
            "name": name,
            "scope": self.scope(entry),
            "encryption": self._profile_values(entry, ["encryption"]),
            "authentication": self._profile_values(entry, ["authentication"]),
            "dh": self._profile_values(entry, ["dh-group"]),
            "lifetime": self._profile_values(entry, ["lifetime"]),
        }

    def lookup_profile(self, profiles, name, scope):
        if not name:
            return None
        if (scope, name) in profiles:
            return profiles[(scope, name)]

        matches = [p for (s, n), p in profiles.items() if n == name]
        if len(matches) == 1:
            return matches[0]
        if matches:
            # Preserve data, but caller should treat correlation cautiously.
            return matches[0]
        return None

    def discover_ike_gateways(self):
        # Definition signature: network/ike/gateway/entry with protocol/local-address/etc.
        for entry in self.root.findall(".//network/ike/gateway/entry"):
            name = entry.get("name")
            if not name:
                continue

            protocol = entry.find("./protocol")
            if protocol is None:
                continue

            version = text_of(entry, "./protocol/version")
            ikev1_profile = text_of(entry, "./protocol/ikev1/ike-crypto-profile")
            ikev2_profile = text_of(entry, "./protocol/ikev2/ike-crypto-profile")

            auth_type = "unknown"
            auth = entry.find("./authentication")
            if auth is not None:
                tags = {c.tag for c in list(auth)}
                if "pre-shared-key" in tags:
                    auth_type = "pre-shared-key"
                elif tags:
                    auth_type = ",".join(sorted(tags))

            gateway = {
                "name": name,
                "scope": self.scope(entry),
                "version": version,
                "ikev1_profile": ikev1_profile,
                "ikev2_profile": ikev2_profile,
                "local_interface": text_of(entry, "./local-address/interface"),
                "local_ip": text_of(entry, "./local-address/ip"),
                "peer_ip": text_of(entry, "./peer-address/ip"),
                "authentication_type": auth_type,
                "nat_traversal": text_of(entry, "./protocol-common/nat-traversal/enable"),
                "fragmentation": text_of(entry, "./protocol-common/fragmentation/enable"),
                "passive_mode": text_of(entry, "./protocol-common/passive-mode"),
                "ikev1_dpd": text_of(entry, "./protocol/ikev1/dpd/enable"),
                "ikev2_dpd": text_of(entry, "./protocol/ikev2/dpd/enable"),
            }
            self.ike_gateways[(gateway["scope"], name)] = gateway

        self.inventory["IKE gateways"] = len(self.ike_gateways)

    def lookup_gateway(self, name, scope):
        if (scope, name) in self.ike_gateways:
            return self.ike_gateways[(scope, name)]
        matches = [g for (s, n), g in self.ike_gateways.items() if n == name]
        return matches[0] if matches else None

    def discover_ipsec_tunnels(self):
        for entry in self.root.findall(".//network/tunnel/ipsec/entry"):
            name = entry.get("name")
            if not name:
                continue

            gateway_names = [
                e.get("name")
                for e in entry.findall("./auto-key/ike-gateway/entry")
                if e.get("name")
            ]

            tunnel = {
                "name": name,
                "scope": self.scope(entry),
                "ike_gateways": gateway_names,
                "ipsec_profile": text_of(entry, "./auto-key/ipsec-crypto-profile"),
                "tunnel_interface": text_of(entry, "./tunnel-interface"),
                "anti_replay": text_of(entry, "./anti-replay"),
                "tunnel_monitor": text_of(entry, "./tunnel-monitor/enable"),
                "disabled": yes(text_of(entry, "./disabled")),
            }
            self.ipsec_tunnels.append(tunnel)

        self.inventory["IPsec tunnels"] = len(self.ipsec_tunnels)

    def weak_values(self, values, baseline_key):
        weak = {normalize_alg(x) for x in self.baseline[baseline_key]}
        return [v for v in values if normalize_alg(v) in weak]

    def assess_vpn(self):
        used_ike_profiles = set()
        used_ipsec_profiles = set()

        for tunnel in self.ipsec_tunnels:
            if tunnel["disabled"]:
                continue

            gateway = None
            if tunnel["ike_gateways"]:
                gateway = self.lookup_gateway(tunnel["ike_gateways"][0], tunnel["scope"])

            ike_profile = None
            if gateway:
                profile_name = gateway["ikev2_profile"] or gateway["ikev1_profile"]
                ike_profile = self.lookup_profile(
                    self.ike_profiles, profile_name, gateway["scope"]
                )
                if profile_name:
                    used_ike_profiles.add(profile_name)

            ipsec_profile = self.lookup_profile(
                self.ipsec_profiles, tunnel["ipsec_profile"], tunnel["scope"]
            )
            if tunnel["ipsec_profile"]:
                used_ipsec_profiles.add(tunnel["ipsec_profile"])

            strong_issues = []
            review_issues = []
            correlation_issues = []

            if gateway:
                if gateway["version"].lower() == "ikev1":
                    review_issues.append("IKEv1 only")
            else:
                correlation_issues.append("Referenced IKE gateway could not be resolved")

            if ike_profile:
                weak_enc = self.weak_values(
                    ike_profile["encryption"], "weak_encryption"
                )
                weak_auth = self.weak_values(
                    ike_profile["authentication"], "weak_hash"
                )
                weak_dh = self.weak_values(
                    ike_profile["dh"], "weak_dh_groups"
                )

                if weak_enc:
                    strong_issues.append(
                        f"Weak IKE encryption: {safe_join(weak_enc)}"
                    )
                if weak_auth:
                    strong_issues.append(
                        f"Weak IKE authentication/hash: {safe_join(weak_auth)}"
                    )
                if weak_dh:
                    strong_issues.append(
                        f"Weak IKE DH group: {safe_join(weak_dh)}"
                    )

            if ipsec_profile:
                weak_enc = self.weak_values(
                    ipsec_profile["encryption"], "weak_encryption"
                )
                weak_auth = self.weak_values(
                    ipsec_profile["authentication"], "weak_hash"
                )
                weak_dh = self.weak_values(
                    ipsec_profile["dh"], "weak_dh_groups"
                )

                uses_gcm = any(
                    "gcm" in normalize_alg(x)
                    for x in ipsec_profile["encryption"]
                )
                auth_none = any(
                    normalize_alg(x) == "none"
                    for x in ipsec_profile["authentication"]
                )

                if weak_enc:
                    strong_issues.append(
                        f"Weak IPsec encryption: {safe_join(weak_enc)}"
                    )
                if weak_auth:
                    strong_issues.append(
                        f"Weak IPsec authentication: {safe_join(weak_auth)}"
                    )
                if weak_dh:
                    strong_issues.append(
                        f"Weak IPsec PFS group: {safe_join(weak_dh)}"
                    )

                if any(
                    normalize_alg(x) == "no-pfs"
                    for x in ipsec_profile["dh"]
                ):
                    review_issues.append("Perfect Forward Secrecy disabled")

                # AES-GCM is authenticated encryption. Do not flag auth=none
                # when GCM is the configured encryption mode.
                if auth_none and not uses_gcm:
                    strong_issues.append(
                        "IPsec authentication is none without detected AES-GCM"
                    )

            elif tunnel["ipsec_profile"]:
                correlation_issues.append(
                    "Referenced IPsec crypto profile could not be resolved"
                )

            if tunnel["anti_replay"].lower() == "no":
                strong_issues.append("IPsec anti-replay disabled")

            context = []
            if gateway:
                context.extend([
                    f"IKE gateway={gateway['name']}",
                    f"IKE version={gateway['version'] or 'not explicit'}",
                    f"IKE profile={(gateway['ikev2_profile'] or gateway['ikev1_profile']) or 'not detected'}",
                ])

            context.extend([
                f"IPsec profile={tunnel['ipsec_profile'] or 'not detected'}",
                f"tunnel-interface={tunnel['tunnel_interface'] or 'not detected'}",
                f"tunnel-monitor={tunnel['tunnel_monitor'] or 'not explicit'}",
            ])

            # Strong cryptographic/anti-replay weaknesses.
            if strong_issues:
                confidence = (
                    "REVIEW REQUIRED"
                    if correlation_issues
                    else "CONFIRMED"
                )
                self.add_finding(
                    "HIGH",
                    confidence,
                    "Site-to-Site VPN",
                    "Weak Security Controls Used by Active IPsec Tunnel",
                    tunnel["name"],
                    "The active IPsec tunnel is correlated to weak cryptographic "
                    "settings or an explicitly disabled anti-replay control.",
                    "; ".join(strong_issues + correlation_issues + context),
                    "Coordinate changes with the remote VPN peer. Replace weak "
                    "cryptographic algorithms/groups with approved stronger options, "
                    "enable anti-replay where applicable, and validate the negotiated "
                    "parameters after the change.",
                    status="ACTIVE",
                    scope=tunnel["scope"],
                )

            # PFS/IKEv1-style posture issues are kept separate so they do not
            # inherit HIGH severity merely because another crypto issue exists.
            if review_issues:
                self.add_finding(
                    "MEDIUM",
                    "REVIEW REQUIRED",
                    "Site-to-Site VPN",
                    "VPN Cryptographic Posture Review",
                    tunnel["name"],
                    "The active IPsec tunnel contains cryptographic posture settings "
                    "that should be reviewed against the organization's VPN baseline.",
                    "; ".join(review_issues + context),
                    "Review the tunnel against the approved VPN cryptographic baseline "
                    "and coordinate any PFS or IKE-version changes with the peer.",
                    status="ACTIVE",
                    scope=tunnel["scope"],
                )

            if correlation_issues and not strong_issues and not review_issues:
                self.add_finding(
                    "LOW",
                    "REVIEW REQUIRED",
                    "Manual Review",
                    "VPN Object Correlation Incomplete",
                    tunnel["name"],
                    "The scanner could not fully correlate one or more referenced VPN objects.",
                    "; ".join(correlation_issues + context),
                    "Verify the referenced gateway and crypto-profile scope/inheritance.",
                    status="UNKNOWN",
                    scope=tunnel["scope"],
                )

        # Weak profiles that exist but were not correlated to an active tunnel.
        for (_, name), profile in self.ike_profiles.items():
            if name in used_ike_profiles:
                continue

            weak = (
                self.weak_values(profile["encryption"], "weak_encryption")
                + self.weak_values(profile["authentication"], "weak_hash")
                + self.weak_values(profile["dh"], "weak_dh_groups")
            )

            if weak:
                self.add_finding(
                    "LOW",
                    "REVIEW REQUIRED",
                    "Manual Review",
                    "Unused/Uncorrelated Weak IKE Crypto Profile",
                    name,
                    "A weak IKE crypto profile exists, but no active IPsec tunnel "
                    "was correlated to it.",
                    f"weak values={safe_join(weak)}",
                    "Remove obsolete profiles or strengthen them to prevent future reuse.",
                    status="UNUSED",
                    scope=profile["scope"],
                )

    # ----------------------------
    # GlobalProtect
    # ----------------------------

    def discover_globalprotect(self):
        for container in self.root.iter("global-protect-portal"):
            for entry in container.findall("./entry"):
                portal = {
                    "name": entry.get("name", ""),
                    "scope": self.scope(entry),
                    "auth_profiles": [
                        x.text.strip()
                        for x in entry.findall(".//client-auth/entry/authentication-profile")
                        if x.text and x.text.strip()
                    ],
                    "credential_or_cert": [
                        x.text.strip()
                        for x in entry.findall(".//client-auth/entry/user-credential-or-client-cert-required")
                        if x.text and x.text.strip()
                    ],
                    "tls_profile": text_of(entry, "./portal-config/ssl-tls-service-profile"),
                    "log_setting": text_of(entry, "./portal-config/log-setting"),
                    "save_credentials": [
                        x.text.strip()
                        for x in entry.findall(".//save-user-credentials")
                        if x.text and x.text.strip()
                    ],
                    "cookie_certs": [
                        x.text.strip()
                        for x in entry.findall(".//cookie-encrypt-decrypt-cert")
                        if x.text and x.text.strip()
                    ],
                }
                self.gp_portals.append(portal)

        for container in self.root.iter("global-protect-gateway"):
            for entry in container.findall("./entry"):
                gateway = {
                    "name": entry.get("name", ""),
                    "scope": self.scope(entry),
                    "auth_profiles": [
                        x.text.strip()
                        for x in entry.findall(".//client-auth/entry/authentication-profile")
                        if x.text and x.text.strip()
                    ],
                    "credential_or_cert": [
                        x.text.strip()
                        for x in entry.findall(".//client-auth/entry/user-credential-or-client-cert-required")
                        if x.text and x.text.strip()
                    ],
                    "tls_profile": text_of(entry, "./ssl-tls-service-profile"),
                    "tunnel_interface": text_of(entry, "./tunnel-interface"),
                    "log_setting": text_of(entry, "./log-setting"),
                    "third_party_ipsec": text_of(entry, "./ipsec/third-party-client/enable"),
                    "split_routes": [
                        x.text.strip()
                        for x in entry.findall(".//split-tunneling/access-route/member")
                        if x.text and x.text.strip()
                    ],
                    "no_direct_local": [
                        x.text.strip()
                        for x in entry.findall(".//no-direct-access-to-local-network")
                        if x.text and x.text.strip()
                    ],
                    "cookie_certs": [
                        x.text.strip()
                        for x in entry.findall(".//cookie-encrypt-decrypt-cert")
                        if x.text and x.text.strip()
                    ],
                    "ip_pools": [
                        x.text.strip()
                        for x in entry.findall(".//ip-pool/member")
                        if x.text and x.text.strip()
                    ],
                }
                self.gp_gateways.append(gateway)

        self.inventory["GlobalProtect portals"] = len(self.gp_portals)
        self.inventory["GlobalProtect gateways"] = len(self.gp_gateways)

    def assess_globalprotect(self):
        for obj_type, objects in (("Portal", self.gp_portals), ("Gateway", self.gp_gateways)):
            for obj in objects:
                issues = []

                # Some gateway objects are infrastructure-only. Only assert missing auth
                # when the object contains signs of remote-user policy.
                remote_user_capable = bool(
                    obj.get("auth_profiles")
                    or obj.get("credential_or_cert")
                    or obj.get("ip_pools")
                    or obj.get("split_routes")
                )

                if remote_user_capable and not obj["auth_profiles"]:
                    issues.append("Authentication profile not detected")

                if remote_user_capable and not obj.get("tls_profile"):
                    issues.append("SSL/TLS service profile not detected")

                if obj.get("third_party_ipsec", "").lower() == "yes":
                    issues.append("Third-party IPsec client support enabled")

                if remote_user_capable and not obj.get("log_setting"):
                    issues.append("Log forwarding setting not detected")

                if issues:
                    self.add_finding(
                        "HIGH" if "Authentication profile not detected" in issues else "MEDIUM",
                        "REVIEW REQUIRED",
                        "GlobalProtect",
                        f"GlobalProtect {obj_type} Security Review",
                        obj["name"],
                        "The GlobalProtect object contains settings that should be validated "
                        "against the remote-access security baseline.",
                        "; ".join(issues),
                        "Verify authentication, TLS, logging, client access and remote-access "
                        "policy settings. Confirm upstream MFA separately when it is enforced "
                        "by an external identity provider.",
                        status="ACTIVE",
                        scope=obj["scope"],
                    )

                if obj["auth_profiles"]:
                    self.add_finding(
                        "INFO",
                        "REVIEW REQUIRED",
                        "Manual Review",
                        "Verify GlobalProtect MFA Enforcement",
                        obj["name"],
                        "An authentication profile is configured, but external MFA enforcement "
                        "cannot be proven from this XML configuration alone.",
                        f"authentication-profile={safe_join(obj['auth_profiles'])}",
                        "Confirm MFA enforcement in the referenced authentication chain or "
                        "external identity provider.",
                        status="ACTIVE",
                        scope=obj["scope"],
                    )

    # ----------------------------
    # Management / protection / auth
    # ----------------------------

    def discover_management_and_protection(self):
        # Interface management profile definitions.
        for container in self.root.iter("interface-management-profile"):
            entries = container.findall("./entry")
            for entry in entries:
                name = entry.get("name")
                if not name:
                    continue
                services = {}
                for service in ("http", "https", "ssh", "telnet", "snmp", "ping", "userid-service"):
                    value = text_of(entry, f"./{service}")
                    if value:
                        services[service] = value

                permitted = []
                p = entry.find("./permitted-ip")
                if p is not None:
                    for child in list(p):
                        value = child.get("name") or text_of(child)
                        if value:
                            permitted.append(value)

                self.mgmt_profiles[(self.scope(entry), name)] = {
                    "name": name,
                    "scope": self.scope(entry),
                    "services": services,
                    "permitted_ip": permitted,
                }

        # References anywhere outside definitions.
        for elem in self.root.iter():
            for child in list(elem):
                if child.tag != "interface-management-profile":
                    continue
                if list(child):  # likely a definition container
                    continue
                value = text_of(child)
                if value:
                    self.mgmt_profile_refs.append({
                        "profile": value,
                        "scope": self.scope(elem),
                        "parent_tag": elem.tag,
                        "parent_name": elem.get("name", ""),
                    })

        for container in self.root.iter("zone-protection-profile"):
            for entry in container.findall("./entry"):
                name = entry.get("name")
                if not name:
                    continue
                self.zone_protection_profiles[(self.scope(entry), name)] = {
                    "name": name,
                    "scope": self.scope(entry),
                    "tcp_syn": text_of(entry, "./flood/tcp-syn/enable"),
                    "udp": text_of(entry, "./flood/udp/enable"),
                    "icmp": text_of(entry, "./flood/icmp/enable"),
                    "icmpv6": text_of(entry, "./flood/icmpv6/enable"),
                    "scan_entries": len(entry.findall("./scan/entry")),
                    "discard_syn_data": text_of(entry, "./discard-tcp-syn-with-data"),
                    "discard_synack_data": text_of(entry, "./discard-tcp-synack-with-data"),
                    "tcp_reject_non_syn": text_of(entry, "./tcp-reject-non-syn"),
                }

        for elem in self.root.iter():
            for child in list(elem):
                if child.tag == "zone-protection-profile" and not list(child):
                    value = text_of(child)
                    if value:
                        self.zone_protection_refs.append({
                            "profile": value,
                            "scope": self.scope(elem),
                            "parent_tag": elem.tag,
                            "parent_name": elem.get("name", ""),
                        })

        for container in self.root.iter("dos-protection"):
            for entry in container.findall("./entry"):
                name = entry.get("name")
                if name:
                    self.dos_profiles[(self.scope(entry), name)] = {
                        "name": name,
                        "scope": self.scope(entry),
                        "tcp_syn": text_of(entry, "./flood/tcp-syn/enable"),
                        "udp": text_of(entry, "./flood/udp/enable"),
                        "icmp": text_of(entry, "./flood/icmp/enable"),
                        "sessions": text_of(entry, "./resource/sessions/enabled"),
                    }

        for container in self.root.iter("authentication-profile"):
            for entry in container.findall("./entry"):
                name = entry.get("name")
                if not name:
                    continue
                self.auth_profiles[(self.scope(entry), name)] = {
                    "name": name,
                    "scope": self.scope(entry),
                    "mfa": text_of(entry, "./multi-factor-auth/mfa-enable"),
                    "lockout_time": text_of(entry, "./lockout/lockout-time"),
                    "failed_attempts": text_of(entry, "./lockout/failed-attempts"),
                    "allow_list": members(entry, "./allow-list"),
                }

        for container in self.root.iter("password-profile"):
            for entry in container.findall("./entry"):
                name = entry.get("name")
                if not name:
                    continue
                self.password_profiles[(self.scope(entry), name)] = {
                    "name": name,
                    "scope": self.scope(entry),
                    "expiration": text_of(entry, "./password-change/expiration-period"),
                    "warning": text_of(entry, "./password-change/expiration-warning-period"),
                }

        self.inventory["Interface management profiles"] = len(self.mgmt_profiles)
        self.inventory["Interface management profile references"] = len(self.mgmt_profile_refs)
        self.inventory["Zone Protection profiles"] = len(self.zone_protection_profiles)
        self.inventory["Zone Protection references"] = len(self.zone_protection_refs)
        self.inventory["DoS protection profiles"] = len(self.dos_profiles)
        self.inventory["Authentication profiles"] = len(self.auth_profiles)
        self.inventory["Password profiles"] = len(self.password_profiles)

    def assess_management(self):
        # Profile-level management checks.
        for (_, name), profile in self.mgmt_profiles.items():
            services = profile["services"]
            issues = []

            if services.get("http", "").lower() == "yes":
                issues.append("HTTP management enabled")
            if services.get("telnet", "").lower() == "yes":
                issues.append("Telnet management enabled")

            unrestricted = any(
                x in {"0.0.0.0/0", "::/0"}
                for x in profile["permitted_ip"]
            )
            if unrestricted:
                issues.append("Unrestricted permitted management IP range")

            if issues:
                self.add_finding(
                    "HIGH" if any("HTTP" in x or "Telnet" in x for x in issues) else "MEDIUM",
                    "CONFIRMED",
                    "Management Plane",
                    "Insecure Interface Management Profile",
                    name,
                    "The interface management profile enables insecure management exposure "
                    "or an unrestricted permitted-address range.",
                    "; ".join(issues),
                    "Disable HTTP/Telnet, use secure management protocols, and restrict "
                    "permitted management sources to dedicated administrative networks.",
                    status="ACTIVE" if any(r["profile"] == name for r in self.mgmt_profile_refs) else "UNKNOWN",
                    scope=profile["scope"],
                )

        # Device system service controls.
        for system in self.root.iter("system"):
            disable_http = text_of(system, "./service/disable-http")
            disable_telnet = text_of(system, "./service/disable-telnet")

            issues = []
            if disable_http and disable_http.lower() != "yes":
                issues.append("Device HTTP service is not disabled")
            if disable_telnet and disable_telnet.lower() != "yes":
                issues.append("Device Telnet service is not disabled")

            if issues:
                self.add_finding(
                    "HIGH",
                    "CONFIRMED",
                    "Management Plane",
                    "Insecure Device Management Service",
                    "system",
                    "The device-level service configuration indicates an insecure management "
                    "protocol may be enabled.",
                    "; ".join(issues),
                    "Disable HTTP and Telnet management services and use HTTPS/SSH from "
                    "restricted administrative networks.",
                    status="ACTIVE",
                    scope=self.scope(system),
                )

    def assess_network_protection(self):
        for (_, name), profile in self.zone_protection_profiles.items():
            disabled = []
            for label, key in (
                ("TCP SYN flood protection", "tcp_syn"),
                ("UDP flood protection", "udp"),
                ("ICMP flood protection", "icmp"),
            ):
                if profile[key] and profile[key].lower() != "yes":
                    disabled.append(label)

            if disabled:
                self.add_finding(
                    "MEDIUM",
                    "REVIEW REQUIRED",
                    "Network Protection",
                    "Zone Protection Controls Disabled",
                    name,
                    "One or more flood-protection controls are explicitly disabled in a "
                    "Zone Protection profile.",
                    safe_join(disabled),
                    "Validate the zone threat model and enable appropriate flood and "
                    "reconnaissance protections with environment-specific thresholds.",
                    status="ACTIVE" if any(r["profile"] == name for r in self.zone_protection_refs) else "UNKNOWN",
                    scope=profile["scope"],
                )

    def assess_authentication(self):
        for (_, name), profile in self.auth_profiles.items():
            issues = []
            if not profile["failed_attempts"]:
                issues.append("Failed-attempt lockout threshold not detected")
            if not profile["lockout_time"]:
                issues.append("Lockout duration not detected")

            if issues:
                self.add_finding(
                    "LOW",
                    "REVIEW REQUIRED",
                    "Authentication Security",
                    "Authentication Lockout Configuration Review",
                    name,
                    "The authentication profile does not expose all expected lockout controls "
                    "in this configuration.",
                    "; ".join(issues),
                    "Confirm failed-login lockout controls are enforced either locally or by "
                    "the upstream identity provider.",
                    status="ACTIVE",
                    scope=profile["scope"],
                )

    # ----------------------------
    # Run
    # ----------------------------

    def run(self):
        self.discover_addresses()
        self.discover_policy()
        self.discover_crypto_profiles()
        self.discover_ike_gateways()
        self.discover_ipsec_tunnels()
        self.discover_globalprotect()
        self.discover_management_and_protection()

        self.assess_security_rules()
        self.assess_decryption_rules()
        self.assess_nat_rules()
        self.assess_vpn()
        self.assess_globalprotect()
        self.assess_management()
        self.assess_network_protection()
        self.assess_authentication()

        self.findings.sort(
            key=lambda x: (
                SECTION_ORDER.index(x["section"])
                if x["section"] in SECTION_ORDER else 999,
                SEVERITY_ORDER.get(x["severity"], 99),
                x["object"],
            )
        )

    def output_data(self):
        # Stable, human-readable IDs used consistently across HTML/PDF/CSV/JSON.
        section_prefix = {
            "Firewall Rules": "FW",
            "Decryption Rules": "DEC",
            "NAT Rules": "NAT",
            "Site-to-Site VPN": "VPN",
            "GlobalProtect": "GP",
            "Management Plane": "MGMT",
            "Threat Prevention": "TP",
            "Logging & Monitoring": "LOG",
            "Network Protection": "NET",
            "Authentication Security": "AUTH",
            "Manual Review": "REV",
        }
        counters = Counter()
        for finding in self.findings:
            prefix = section_prefix.get(finding.get("section"), "CFG")
            counters[prefix] += 1
            finding["finding_id"] = f"PA-{prefix}-{counters[prefix]:03d}"

        return {
            "metadata": {
                "scanner": "H4wkEye",
                "version": VERSION,
                "scanner_version": VERSION,
                "configuration": self.xml_path.name,
                "generated": datetime.now().isoformat(timespec="seconds"),
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "offline": True,
                "network_requests": 0,
                "secret_values_redacted": self.redacted_secret_values,
            },
            "inventory": dict(sorted(self.inventory.items())),
            "rule_statistics": dict(sorted(self.rule_statistics.items())),
            "relationships": {
                "ike_gateways": list(self.ike_gateways.values()),
                "ipsec_tunnels": self.ipsec_tunnels,
            },
            "vpn_inventory": self.build_vpn_inventory(),
            "globalprotect_inventory": {
                "portals": self.gp_portals,
                "gateways": self.gp_gateways,
            },
            "findings": self.findings,
        }

    def build_vpn_inventory(self):
        rows = []
        for tunnel in self.ipsec_tunnels:
            gateway = (
                self.lookup_gateway(tunnel["ike_gateways"][0], tunnel["scope"])
                if tunnel["ike_gateways"] else None
            )

            ike_profile = None
            if gateway:
                profile_name = gateway["ikev2_profile"] or gateway["ikev1_profile"]
                ike_profile = self.lookup_profile(self.ike_profiles, profile_name, gateway["scope"])

            ipsec_profile = self.lookup_profile(
                self.ipsec_profiles, tunnel["ipsec_profile"], tunnel["scope"]
            )

            rows.append({
                "tunnel": tunnel["name"],
                "scope": tunnel["scope"],
                "tunnel_interface": tunnel["tunnel_interface"],
                "ike_gateway": gateway["name"] if gateway else safe_join(tunnel["ike_gateways"]),
                "peer_address": gateway["peer_ip"] if gateway else "",
                "local_interface": gateway["local_interface"] if gateway else "",
                "ike_version": gateway["version"] if gateway else "",
                "authentication_type": gateway["authentication_type"] if gateway else "",
                "ike_profile": (
                    gateway["ikev2_profile"] or gateway["ikev1_profile"]
                    if gateway else ""
                ),
                "ike_encryption": safe_join(ike_profile["encryption"]) if ike_profile else "",
                "ike_authentication": safe_join(ike_profile["authentication"]) if ike_profile else "",
                "ike_dh": safe_join(ike_profile["dh"]) if ike_profile else "",
                "ipsec_profile": tunnel["ipsec_profile"],
                "ipsec_encryption": safe_join(ipsec_profile["encryption"]) if ipsec_profile else "",
                "ipsec_authentication": safe_join(ipsec_profile["authentication"]) if ipsec_profile else "",
                "pfs": safe_join(ipsec_profile["dh"]) if ipsec_profile else "",
                "anti_replay": tunnel["anti_replay"],
                "tunnel_monitor": tunnel["tunnel_monitor"],
            })
        return rows


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_csv(path, findings):
    fields = [
        "finding_id",
        "severity", "confidence", "status", "section", "title", "object",
        "scope", "risk_score", "source_zones", "source_objects",
        "resolved_sources", "destination_zones", "destination_objects",
        "resolved_destinations", "applications", "services",
        "description", "evidence", "remediation",
    ]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)


def write_html(path, data):
    import html
    from collections import Counter

    def esc(value):
        if value is None:
            return ""
        if isinstance(value, list):
            value = ", ".join(str(x) for x in value)
        return html.escape(str(value))

    findings = data.get("findings", [])
    inventory = data.get("inventory", {})
    rule_stats = data.get("rule_statistics", {})
    vpn_inventory = data.get("vpn_inventory", [])

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_counts = Counter(x.get("severity", "INFO") for x in findings)
    section_counts = Counter(x.get("section", "Other") for x in findings)

    confirmed = sum(1 for x in findings if x.get("confidence") == "CONFIRMED")
    review = sum(1 for x in findings if x.get("confidence") == "REVIEW REQUIRED")
    high_critical = sev_counts["CRITICAL"] + sev_counts["HIGH"]
    overall = ("CRITICAL" if sev_counts["CRITICAL"] else
               "HIGH" if sev_counts["HIGH"] else
               "MEDIUM" if sev_counts["MEDIUM"] else
               "LOW" if sev_counts["LOW"] else "INFO")

    allow_rules = int(rule_stats.get("Enabled allow rules", 0) or 0)
    app_any = int(rule_stats.get("Allow rules: application any", 0) or 0)
    service_any = int(rule_stats.get("Allow rules: service any", 0) or 0)
    no_profile = int(rule_stats.get("Allow rules: no security profile", 0) or 0)
    app_default = int(rule_stats.get("Allow rules: application-default", 0) or 0)
    reportable_high = int(rule_stats.get("Reportable broad rules: high", 0) or 0)
    reportable_medium = int(rule_stats.get("Reportable broad rules: medium", 0) or 0)

    def pct(n, d):
        return f"{(100*n/d):.1f}%" if d else "N/A"

    observations = []
    if allow_rules:
        observations.append(
            f"{app_any:,} of {allow_rules:,} enabled allow rules ({pct(app_any, allow_rules)}) "
            "use application=any. This is a policy-maturity metric, not an individual vulnerability."
        )
        observations.append(
            f"{service_any:,} enabled allow rules use service=any; "
            f"{app_default:,} use application-default."
        )
        observations.append(
            f"{no_profile:,} enabled allow rules have no detected Security Profile Group "
            "or individual security profiles."
        )
    if reportable_high or reportable_medium:
        observations.append(
            f"The contextual rule engine identified {reportable_high} High and "
            f"{reportable_medium} Medium broad allow rules requiring review."
        )

    severity_cards = "".join(
        f'<div class="metric severity-{s.lower()}"><div class="metric-label">{s.title()}</div>'
        f'<div class="metric-value">{sev_counts[s]}</div></div>'
        for s in sev_order
    )

    max_count = max([sev_counts[s] for s in sev_order] + [1])
    bars = "".join(
        f'<div class="bar-row"><span>{s.title()}</span><div class="bar-track">'
        f'<div class="bar severity-bg-{s.lower()}" style="width:{(sev_counts[s]/max_count)*100:.1f}%"></div>'
        f'</div><strong>{sev_counts[s]}</strong></div>'
        for s in sev_order
    )

    section_rows = "".join(
        f"<tr><td>{esc(section)}</td><td>{count}</td></tr>"
        for section, count in section_counts.most_common()
    ) or '<tr><td colspan="2">No findings.</td></tr>'

    section_order = [
        "Firewall Rules", "Decryption Rules", "NAT Rules", "Site-to-Site VPN",
        "GlobalProtect", "Management Plane", "Threat Prevention",
        "Logging & Monitoring", "Network Protection",
        "Authentication Security", "Manual Review"
    ]
    ordered_sections = [s for s in section_order if s in section_counts]
    ordered_sections += [s for s in section_counts if s not in section_order]

    findings_html = []
    for section in ordered_sections:
        items = [x for x in findings if x.get("section") == section]
        sc = Counter(x.get("severity") for x in items)
        cards = []
        for x in items:
            sev = x.get("severity", "INFO")
            context_rows = []
            fields = [
                ("Object", x.get("object")), ("Scope", x.get("scope")),
                ("Status", x.get("status")), ("Confidence", x.get("confidence")),
                ("Risk Score", x.get("risk_score")),
                ("Source Zones", x.get("source_zones")),
                ("Source Objects", x.get("source_objects")),
                ("Resolved Sources", x.get("resolved_sources")),
                ("Destination Zones", x.get("destination_zones")),
                ("Destination Objects", x.get("destination_objects")),
                ("Resolved Destinations", x.get("resolved_destinations")),
                ("Applications", x.get("applications")), ("Services", x.get("services")),
            ]
            for label, value in fields:
                if value not in (None, "", [], {}):
                    context_rows.append(f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>")

            cards.append(
                '<article class="finding">'
                '<div class="finding-head"><div>'
                f'<span class="badge severity-{sev.lower()}">{esc(sev)}</span>'
                f'<span class="finding-id">{esc(x.get("finding_id",""))}</span>'
                f'<h3>{esc(x.get("title"))}</h3></div>'
                f'<div class="confidence">{esc(x.get("confidence"))}</div></div>'
                f'<p class="description">{esc(x.get("description"))}</p>'
                '<div class="finding-grid"><div><h4>Evidence</h4>'
                f'<div class="evidence">{esc(x.get("evidence"))}</div></div>'
                '<div><h4>Remediation</h4>'
                f'<div class="remediation">{esc(x.get("remediation"))}</div></div></div>'
                '<details><summary>Technical context</summary>'
                f'<table class="context-table">{"".join(context_rows)}</table></details>'
                '</article>'
            )

        chips = " ".join(
            f'<span class="chip severity-{s.lower()}">{s.title()}: {sc[s]}</span>'
            for s in sev_order if sc[s]
        )
        findings_html.append(
            f'<section class="report-section"><div class="section-title">'
            f'<h2>{esc(section)}</h2><div>{chips}</div></div>{"".join(cards)}</section>'
        )

    rule_stats_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{int(v):,}</td></tr>"
        for k, v in rule_stats.items()
    ) or '<tr><td colspan="2">No security-rule statistics available.</td></tr>'

    vpn_rows_list = []
    for v in vpn_inventory:
        vpn_rows_list.append(
            "<tr>"
            f"<td>{esc(v.get('tunnel_name') or v.get('name'))}</td>"
            f"<td>{esc(v.get('ike_gateway'))}</td>"
            f"<td>{esc(v.get('ike_version'))}</td>"
            f"<td>{esc(v.get('ike_profile'))}</td>"
            f"<td>{esc(v.get('ipsec_profile'))}</td>"
            f"<td>{esc(v.get('tunnel_interface'))}</td>"
            f"<td>{esc(v.get('anti_replay'))}</td>"
            f"<td>{esc(v.get('tunnel_monitor'))}</td>"
            "</tr>"
        )
    vpn_rows = "".join(vpn_rows_list) or '<tr><td colspan="8">No IPsec tunnel inventory available.</td></tr>'

    inv_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
        for k, v in inventory.items()
    )
    observation_html = "".join(f"<li>{esc(x)}</li>" for x in observations)

    meta = data.get("metadata", {})
    generated = esc(meta.get("generated_at", ""))
    config_name = esc(meta.get("configuration", "PAN-OS XML configuration"))
    scanner_version = esc(meta.get("scanner_version", VERSION))
    logo_uri = load_logo_data_uri()
    logo_html = (f'<img class="brand-logo" src="{logo_uri}" alt="H4wkEye logo">' if logo_uri else '<div class="brand-word">H4wkEye</div>')

    doc = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PAN-OS Offline Security Assessment</title>
<style>
:root{{--bg:#f4f7fb;--surface:#fff;--ink:#172033;--muted:#657189;--line:#dfe5ee;--navy:#16233b;--critical:#8f1d2c;--high:#b94332;--medium:#a86b00;--low:#3867a8;--info:#64748b}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Arial,sans-serif}}
header{{background:var(--navy);color:white;padding:24px 5vw}} .brand{{display:flex;align-items:center;gap:22px}} .brand-logo{{width:112px;height:112px;object-fit:contain;border-radius:12px;background:white}} .brand-word{{font-size:28px;font-weight:800}} header h1{{margin:0 0 6px;font-size:30px}}
header p{{margin:4px 0;opacity:.82}} main{{max-width:1280px;margin:auto;padding:28px 24px 60px}}
.hero{{display:grid;grid-template-columns:1.25fr .75fr;gap:20px}} .panel,.finding{{background:white;border:1px solid var(--line);border-radius:12px;box-shadow:0 2px 8px rgba(30,45,70,.05)}}
.panel{{padding:22px}} .risk-pill{{display:inline-block;padding:7px 12px;border-radius:999px;color:white;font-weight:700}}
.metrics{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:20px 0}}
.metric{{background:white;border:1px solid var(--line);border-top:4px solid currentColor;border-radius:10px;padding:15px}}
.metric-label{{color:var(--muted);font-size:12px;text-transform:uppercase}} .metric-value{{font-size:27px;font-weight:700}}
.severity-critical{{color:var(--critical)}} .severity-high{{color:var(--high)}} .severity-medium{{color:var(--medium)}} .severity-low{{color:var(--low)}} .severity-info{{color:var(--info)}}
.badge.severity-critical,.risk-pill.severity-critical{{background:var(--critical);color:white}} .badge.severity-high,.risk-pill.severity-high{{background:var(--high);color:white}}
.badge.severity-medium,.risk-pill.severity-medium{{background:var(--medium);color:white}} .badge.severity-low,.risk-pill.severity-low{{background:var(--low);color:white}} .badge.severity-info,.risk-pill.severity-info{{background:var(--info);color:white}}
.severity-bg-critical{{background:var(--critical)}} .severity-bg-high{{background:var(--high)}} .severity-bg-medium{{background:var(--medium)}} .severity-bg-low{{background:var(--low)}} .severity-bg-info{{background:var(--info)}}
.bar-row{{display:grid;grid-template-columns:70px 1fr 35px;align-items:center;gap:10px;margin:10px 0}} .bar-track{{height:9px;background:#edf1f6;border-radius:8px;overflow:hidden}} .bar{{height:100%;border-radius:8px}}
.grid-2{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:20px 0}} table{{width:100%;border-collapse:collapse;background:white}}
th,td{{text-align:left;border-bottom:1px solid var(--line);padding:9px 10px;vertical-align:top}} th{{color:#44516a;background:#f8fafc}}
.report-section{{margin-top:32px}} .section-title{{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--navy);margin-bottom:15px}}
.section-title h2{{margin:0 0 9px}} .chip,.badge{{display:inline-block;border-radius:999px;padding:4px 9px;font-size:11px;font-weight:700}} .chip{{background:#eef2f7;margin-left:4px}}
.finding{{margin:13px 0;padding:18px}} .finding-head{{display:flex;justify-content:space-between;gap:15px}} .finding-head h3{{margin:8px 0 3px;font-size:18px}}
.finding-id{{margin-left:8px;color:var(--muted);font-family:monospace}} .confidence{{color:var(--muted);font-size:12px;font-weight:700}}
.description{{color:#3e4a60}} .finding-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}} .finding-grid h4{{margin:0 0 6px}}
.evidence,.remediation{{background:#f8fafc;border-left:3px solid #cbd5e1;padding:10px 12px;min-height:62px}}
details{{margin-top:13px}} summary{{cursor:pointer;color:#3457d5;font-weight:700}} .context-table{{margin-top:10px}} .context-table th{{width:180px}} .note{{color:var(--muted)}}
@media(max-width:850px){{.hero,.grid-2,.finding-grid{{grid-template-columns:1fr}}.metrics{{grid-template-columns:repeat(2,1fr)}}}}
@media print{{body{{background:white}}.panel,.finding{{box-shadow:none;break-inside:avoid}}}}
</style></head><body>
<header><div class="brand">{logo_html}<div><h1>H4wkEye</h1><p><strong>Offline PAN-OS Configuration Security Assessment</strong></p><p>Configuration: {config_name}</p><p>v{scanner_version} • Generated {generated} • Privacy: {esc(meta.get("privacy_mode", "standard"))}</p></div></div></header>
<main>
<div class="hero">
<section class="panel"><h2>Executive Summary</h2><p><span class="risk-pill severity-{overall.lower()}">Overall assessment: {overall}</span></p>
<p>The assessment identified <strong>{len(findings)}</strong> findings. <strong>{high_critical}</strong> are High/Critical priority, <strong>{confirmed}</strong> are confirmed by configuration evidence, and <strong>{review}</strong> require contextual validation.</p>
<ul>{observation_html}</ul></section>
<section class="panel"><h2>Risk Distribution</h2>{bars}<p class="note">Business impact and live reachability can change final risk.</p></section>
</div>
<div class="metrics">{severity_cards}</div>
<div class="grid-2">
<section class="panel"><h2>Findings by Area</h2><table><tr><th>Assessment Area</th><th>Findings</th></tr>{section_rows}</table></section>
<section class="panel"><h2>How to Read This Report</h2><p><strong>Confirmed</strong> means configuration evidence was directly correlated. <strong>Review Required</strong> means business context, exposure, peer configuration, or an external service must still be validated.</p><p>Isolated <code>any</code> values are not treated as vulnerabilities. Explicit App-ID with <code>application-default</code> is treated as a mitigating pattern.</p></section>
</div>
<section class="panel"><h2>Security Rule Posture</h2><p class="note">Prevalence statistics, not individual vulnerabilities.</p><table><tr><th>Statistic</th><th>Count</th></tr>{rule_stats_rows}</table></section>
{"".join(findings_html)}
<section class="report-section"><div class="section-title"><h2>Site-to-Site VPN Inventory</h2></div><div class="panel"><table>
<tr><th>Tunnel</th><th>IKE Gateway</th><th>IKE Version</th><th>IKE Profile</th><th>IPsec Profile</th><th>Interface</th><th>Anti-Replay</th><th>Monitor</th></tr>{vpn_rows}
</table></div></section>
<section class="report-section"><div class="section-title"><h2>Configuration Inventory</h2></div><div class="panel"><table><tr><th>Object Type</th><th>Count</th></tr>{inv_rows}</table></div></section>
<section class="report-section"><div class="section-title"><h2>Methodology & Limitations</h2></div><div class="panel">
<p>This is a static offline assessment of PAN-OS XML configuration. It does not test live reachability, negotiated VPN parameters, external identity-provider behavior, runtime dynamic address-group membership, traffic logs, or business justification.</p>
<p>Findings should be validated by an assessor before being treated as final vulnerabilities. CSV and JSON outputs retain machine-readable evidence.</p>
</div></section>
</main><footer style="text-align:center;padding:28px;color:#657189">H4wkEye v{scanner_version} • Offline Configuration Security Scanner</footer>
</body></html>'''

    Path(path).write_text(doc, encoding="utf-8")



def write_pdf(path, data):
    """Generate a self-contained PDF from the already privacy-sanitized report data."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
            Image, KeepTogether, HRFlowable
        )
    except ImportError as exc:
        raise RuntimeError(
            "PDF output requires ReportLab. Install it offline/from your approved package "
            "source with: python3 -m pip install reportlab"
        ) from exc

    findings = data.get("findings", [])
    inventory = data.get("inventory", {})
    rule_stats = data.get("rule_statistics", {})
    vpn_inventory = data.get("vpn_inventory", [])
    meta = data.get("metadata", {})

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_counts = Counter(x.get("severity", "INFO") for x in findings)
    section_counts = Counter(x.get("section", "Other") for x in findings)
    confirmed = sum(1 for x in findings if x.get("confidence") == "CONFIRMED")
    review = sum(1 for x in findings if x.get("confidence") == "REVIEW REQUIRED")
    high_critical = sev_counts["CRITICAL"] + sev_counts["HIGH"]
    overall = ("CRITICAL" if sev_counts["CRITICAL"] else
               "HIGH" if sev_counts["HIGH"] else
               "MEDIUM" if sev_counts["MEDIUM"] else
               "LOW" if sev_counts["LOW"] else "INFO")

    palette = {
        "navy": colors.HexColor("#16233B"),
        "ink": colors.HexColor("#172033"),
        "muted": colors.HexColor("#657189"),
        "line": colors.HexColor("#DFE5EE"),
        "panel": colors.HexColor("#F7F9FC"),
        "CRITICAL": colors.HexColor("#8F1D2C"),
        "HIGH": colors.HexColor("#B94332"),
        "MEDIUM": colors.HexColor("#A86B00"),
        "LOW": colors.HexColor("#3867A8"),
        "INFO": colors.HexColor("#64748B"),
    }

    def txt(value):
        if value is None:
            return ""
        if isinstance(value, list):
            value = ", ".join(str(x) for x in value)
        value = str(value)
        # Escape ReportLab Paragraph markup and keep output renderer-safe.
        return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                     .replace("•", "-").replace("–", "-").replace("—", "-"))

    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "H4wkTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=24, leading=28, textColor=palette["navy"], spaceAfter=6
    )
    subtitle = ParagraphStyle(
        "H4wkSubtitle", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=palette["muted"], spaceAfter=3
    )
    h1 = ParagraphStyle(
        "H4wkH1", parent=styles["Heading1"], fontName="Helvetica-Bold",
        fontSize=17, leading=21, textColor=palette["navy"], spaceBefore=8, spaceAfter=10
    )
    h2 = ParagraphStyle(
        "H4wkH2", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=13, leading=16, textColor=palette["navy"], spaceBefore=7, spaceAfter=6
    )
    body = ParagraphStyle(
        "H4wkBody", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=8.6, leading=12, textColor=palette["ink"], spaceAfter=5
    )
    small = ParagraphStyle(
        "H4wkSmall", parent=body, fontSize=7.2, leading=9.2, textColor=palette["muted"]
    )
    label = ParagraphStyle(
        "H4wkLabel", parent=small, fontName="Helvetica-Bold", textColor=palette["navy"]
    )
    finding_title = ParagraphStyle(
        "H4wkFinding", parent=styles["Heading3"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=palette["ink"], spaceAfter=5
    )
    white_center = ParagraphStyle(
        "WhiteCenter", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=9, leading=11, textColor=colors.white, alignment=TA_CENTER
    )

    def P(value, style=body):
        return Paragraph(txt(value), style)

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(palette["line"])
        canvas.line(18*mm, 13*mm, A4[0]-18*mm, 13*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(palette["muted"])
        canvas.drawString(18*mm, 8*mm, f"H4wkEye v{VERSION} - Offline Configuration Security Scanner")
        canvas.drawRightString(A4[0]-18*mm, 8*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(path), pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
        topMargin=15*mm, bottomMargin=18*mm,
        title="H4wkEye PAN-OS Security Assessment",
        author="H4wkEye"
    )
    story = []

    # Cover / brand
    logo_path = Path(__file__).resolve().parent / "assets" / "h4wk-logo.png"
    if logo_path.is_file():
        img = Image(str(logo_path), width=38*mm, height=38*mm)
        img.hAlign = "CENTER"
        story += [Spacer(1, 10*mm), img, Spacer(1, 4*mm)]
    story += [
        Paragraph("H4wkEye", title),
        Paragraph("Offline PAN-OS Configuration Security Assessment", subtitle),
        Spacer(1, 4*mm),
        P(f"Configuration: {meta.get('configuration','')}", body),
        P(f"Scanner version: {meta.get('scanner_version', VERSION)}", body),
        P(f"Generated: {meta.get('generated_at', meta.get('generated',''))}", body),
        P(f"Privacy mode: {meta.get('privacy_mode','standard')}", body),
        Spacer(1, 4*mm),
        HRFlowable(width="100%", thickness=1.2, color=palette["navy"]),
        Spacer(1, 5*mm),
        Paragraph("Executive Summary", h1),
        P(
            f"Overall assessment: {overall}. The assessment identified {len(findings)} findings. "
            f"{high_critical} are High/Critical priority, {confirmed} are confirmed by configuration "
            f"evidence, and {review} require contextual validation."
        ),
    ]

    # Severity summary cards
    sev_table = [[P(s.title(), white_center) for s in sev_order],
                 [P(str(sev_counts[s]), finding_title) for s in sev_order]]
    t = Table(sev_table, colWidths=[33*mm]*5)
    ts = [
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("GRID", (0,0), (-1,-1), 0.4, palette["line"]),
        ("BACKGROUND", (0,1), (-1,1), colors.white),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]
    for i, sev in enumerate(sev_order):
        ts.append(("BACKGROUND", (i,0), (i,0), palette[sev]))
    t.setStyle(TableStyle(ts))
    story += [Spacer(1, 4*mm), t, Spacer(1, 6*mm)]

    allow_rules = int(rule_stats.get("Enabled allow rules", 0) or 0)
    app_any = int(rule_stats.get("Allow rules: application any", 0) or 0)
    service_any = int(rule_stats.get("Allow rules: service any", 0) or 0)
    no_profile = int(rule_stats.get("Allow rules: no security profile", 0) or 0)
    app_default = int(rule_stats.get("Allow rules: application-default", 0) or 0)
    if allow_rules:
        story += [
            Paragraph("Key Observations", h2),
            P(f"- {app_any:,} of {allow_rules:,} enabled allow rules "
              f"({(100*app_any/allow_rules):.1f}%) use application=any. "
              "This is a policy-maturity metric, not an individual vulnerability."),
            P(f"- {service_any:,} enabled allow rules use service=any; "
              f"{app_default:,} use application-default."),
            P(f"- {no_profile:,} enabled allow rules have no detected Security Profile Group "
              "or individual security profiles."),
        ]

    story += [Paragraph("Findings by Area", h2)]
    area_data = [[P("Assessment Area", label), P("Findings", label)]]
    area_data += [[P(k, body), P(str(v), body)] for k, v in section_counts.most_common()]
    at = Table(area_data, colWidths=[135*mm, 30*mm], repeatRows=1)
    at.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),palette["panel"]),
        ("GRID",(0,0),(-1,-1),0.35,palette["line"]),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
    ]))
    story += [at, PageBreak()]

    # Findings
    story += [Paragraph("Detailed Findings", h1)]
    section_order = [
        "Firewall Rules", "Decryption Rules", "NAT Rules", "Site-to-Site VPN",
        "GlobalProtect", "Management Plane", "Threat Prevention",
        "Logging & Monitoring", "Network Protection",
        "Authentication Security", "Manual Review"
    ]
    ordered_sections = [s for s in section_order if s in section_counts]
    ordered_sections += [s for s in section_counts if s not in section_order]

    for section in ordered_sections:
        story += [Paragraph(section, h1)]
        for x in [f for f in findings if f.get("section") == section]:
            sev = x.get("severity", "INFO")
            header = Table(
                [[P(sev, white_center),
                  P(x.get("finding_id",""), label),
                  P(x.get("title",""), finding_title)]],
                colWidths=[23*mm, 27*mm, 115*mm]
            )
            header.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(0,0),palette.get(sev,palette["INFO"])),
                ("BACKGROUND",(1,0),(-1,0),palette["panel"]),
                ("GRID",(0,0),(-1,-1),0.35,palette["line"]),
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
            ]))

            detail_rows = [
                [P("Confidence", label), P(x.get("confidence",""), body),
                 P("Status", label), P(x.get("status",""), body)],
                [P("Object", label), P(x.get("object",""), body),
                 P("Scope", label), P(x.get("scope",""), small)],
            ]
            if x.get("risk_score") not in (None, ""):
                detail_rows.append([P("Risk Score", label), P(x.get("risk_score"), body),
                                    P("", label), P("", body)])
            details = Table(detail_rows, colWidths=[23*mm, 57*mm, 23*mm, 62*mm])
            details.setStyle(TableStyle([
                ("GRID",(0,0),(-1,-1),0.3,palette["line"]),
                ("BACKGROUND",(0,0),(0,-1),palette["panel"]),
                ("BACKGROUND",(2,0),(2,-1),palette["panel"]),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
                ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
            ]))

            block = [
                header, Spacer(1,2*mm), details, Spacer(1,2*mm),
                Paragraph("Description", h2), P(x.get("description","")),
                Paragraph("Evidence", h2), P(x.get("evidence","")),
                Paragraph("Remediation", h2), P(x.get("remediation","")),
            ]

            context_fields = [
                ("Source Zones", x.get("source_zones")),
                ("Source Objects", x.get("source_objects")),
                ("Resolved Sources", x.get("resolved_sources")),
                ("Destination Zones", x.get("destination_zones")),
                ("Destination Objects", x.get("destination_objects")),
                ("Resolved Destinations", x.get("resolved_destinations")),
                ("Applications", x.get("applications")),
                ("Services", x.get("services")),
            ]
            context_rows = [[P(k,label), P(v,small)] for k,v in context_fields if v not in (None,"",[],{})]
            if context_rows:
                ct = Table(context_rows, colWidths=[35*mm,130*mm])
                ct.setStyle(TableStyle([
                    ("GRID",(0,0),(-1,-1),0.25,palette["line"]),
                    ("BACKGROUND",(0,0),(0,-1),palette["panel"]),
                    ("VALIGN",(0,0),(-1,-1),"TOP"),
                    ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
                ]))
                block += [Paragraph("Technical Context", h2), ct]
            block += [Spacer(1,5*mm)]
            story += block

    # Security rule posture
    story += [PageBreak(), Paragraph("Security Rule Posture", h1),
              P("These are configuration prevalence statistics, not individual vulnerabilities.", small)]
    rs = [[P("Statistic",label), P("Count",label)]]
    rs += [[P(k,body), P(f"{int(v):,}",body)] for k,v in rule_stats.items()]
    rt = Table(rs, colWidths=[135*mm,30*mm], repeatRows=1)
    rt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),palette["panel"]),
        ("GRID",(0,0),(-1,-1),0.3,palette["line"]),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]))
    story += [rt]

    # VPN inventory, compact but useful.
    story += [Spacer(1,7*mm), Paragraph("Site-to-Site VPN Inventory", h1)]
    vpn_data = [[P(x,label) for x in ("Tunnel","IKE Gateway","IKE","IKE Profile","IPsec Profile","Anti-Replay")]]
    for v in vpn_inventory:
        vpn_data.append([
            P(v.get("tunnel") or v.get("name"), small),
            P(v.get("ike_gateway"), small),
            P(v.get("ike_version"), small),
            P(v.get("ike_profile"), small),
            P(v.get("ipsec_profile"), small),
            P(v.get("anti_replay"), small),
        ])
    if len(vpn_data) == 1:
        vpn_data.append([P("No IPsec tunnel inventory available.",small),"","","","",""])
    vt = Table(vpn_data, colWidths=[31*mm,31*mm,20*mm,31*mm,31*mm,21*mm], repeatRows=1)
    vt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),palette["panel"]),
        ("GRID",(0,0),(-1,-1),0.25,palette["line"]),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
    ]))
    story += [vt]

    story += [Spacer(1,7*mm), Paragraph("Configuration Inventory", h1)]
    inv = [[P("Object Type",label),P("Count",label)]]
    inv += [[P(k,body),P(v,body)] for k,v in inventory.items()]
    it = Table(inv, colWidths=[135*mm,30*mm], repeatRows=1)
    it.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),palette["panel"]),
        ("GRID",(0,0),(-1,-1),0.3,palette["line"]),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]))
    story += [it, Spacer(1,7*mm), Paragraph("Methodology & Limitations", h1),
              P("This is a static offline assessment of PAN-OS XML configuration. It does not test "
                "live reachability, negotiated VPN parameters, external identity-provider behavior, "
                "runtime dynamic address-group membership, traffic logs, or business justification."),
              P("Findings should be validated by an assessor before being treated as final "
                "vulnerabilities. The PDF is generated only from the same privacy-sanitized data "
                "used for the HTML, CSV and JSON reports.")]

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    chmod_private(path)


def load_baseline(path):
    baseline = json.loads(json.dumps(DEFAULT_BASELINE))
    if not path:
        return baseline

    custom = json.loads(Path(path).read_text(encoding="utf-8"))

    def merge(dst, src):
        for k, v in src.items():
            if isinstance(v, dict) and isinstance(dst.get(k), dict):
                merge(dst[k], v)
            else:
                dst[k] = v

    merge(baseline, custom)
    return baseline


def main():
    parser = argparse.ArgumentParser(
        description="H4wkEye - offline PAN-OS XML security configuration scanner"
    )
    parser.add_argument("xml", help="PAN-OS XML configuration backup")
    parser.add_argument(
        "--output", default=".", help="Output directory (default: current directory)"
    )
    parser.add_argument(
        "--baseline", help="Optional JSON baseline override"
    )
    parser.add_argument(
        "--privacy", choices=("standard", "strict"), default="standard",
        help="Report privacy mode. standard keeps operational identifiers; strict pseudonymizes them. Secrets are always redacted."
    )
    args = parser.parse_args()

    xml_path = Path(args.xml)
    if not xml_path.is_file():
        print(f"[!] Configuration not found: {xml_path}", file=sys.stderr)
        return 2

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    try:
        baseline = load_baseline(args.baseline)
        scanner = Scanner(xml_path, baseline)
        scanner.run()
        data = scanner.output_data()
        privacy_salt = secrets.token_hex(16)
        data = apply_privacy(data, args.privacy, privacy_salt)
    except ET.ParseError as exc:
        print(f"[!] Invalid XML: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"[!] Scanner error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4

    json_path = out / "H4wkEye-report.json"
    csv_path = out / "H4wkEye-report.csv"
    html_path = out / "H4wkEye-report.html"
    pdf_path = out / "H4wkEye-report.pdf"

    write_json(json_path, data)
    write_csv(csv_path, data["findings"])
    write_html(html_path, data)
    try:
        write_pdf(pdf_path, data)
    except RuntimeError as exc:
        print(f"[!] PDF generation failed: {exc}", file=sys.stderr)
        return 5
    for report_path in (json_path, csv_path, html_path, pdf_path):
        chmod_private(report_path)

    counts = Counter(f["severity"] for f in data["findings"])

    print("=" * 72)
    print(f"H4wkEye v{VERSION} - Offline PAN-OS Configuration Security Scanner")
    print("=" * 72)
    print(f"Configuration : {xml_path.name}")
    print(f"Privacy mode  : {args.privacy}")
    print(f"Secrets       : redacted before analysis ({data['metadata'].get('secret_values_redacted', 0)} values)")
    print("Network       : no network functionality")
    print(f"Findings      : {len(data['findings'])}")
    print(
        "Severity      : "
        f"Critical={counts['CRITICAL']} "
        f"High={counts['HIGH']} "
        f"Medium={counts['MEDIUM']} "
        f"Low={counts['LOW']} "
        f"Info={counts['INFO']}"
    )
    print(f"IPsec tunnels : {len(data['vpn_inventory'])}")
    print(f"HTML report   : {html_path}")
    print(f"PDF report    : {pdf_path}")
    print(f"CSV report    : {csv_path}")
    print(f"JSON report   : {json_path}")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
