#!/usr/bin/env python3
"""
H4wkEye v3.0.10
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

VERSION = "3.1.0-preview.8"

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


MAX_XML_BYTES = 100 * 1024 * 1024  # Overridden by --max-xml-mib in main()
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
        if self.xml_path.stat().st_size == 0:
            raise ValueError("EMPTY_FILE: XML input is zero bytes")
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
        self.resolution_statistics = Counter()

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
        """Only the current policy scope and Panorama shared objects are eligible.

        No device-group parent inheritance is assumed. Device-local/vsys scopes
        never borrow objects from unrelated device groups.
        """
        requested_scope = requested_scope or "device/local"
        candidates = [requested_scope]
        # In Panorama exports the shared subtree is identified by this exact key.
        if requested_scope != "shared":
            candidates.append("shared")
        return candidates

    def lookup_address(self, name, scope):
        """Resolve in scope, then shared. Never guess across device groups.

        Returns (object_tuple, ambiguous). A same-scope address/group collision
        is explicitly ambiguous rather than silently selecting an arbitrary one.
        """
        for candidate in self.candidate_scopes(scope):
            matches = []
            if name in self.addresses.get(candidate, {}):
                matches.append(("address", candidate, self.addresses[candidate][name]))
            if name in self.address_groups.get(candidate, {}):
                matches.append(("group", candidate, self.address_groups[candidate][name]))
            if len(matches) > 1:
                self.resolution_statistics["ambiguous_same_scope"] += 1
                return None, True
            if matches:
                self.resolution_statistics["resolved_local" if candidate == scope else "resolved_shared"] += 1
                return matches[0], False
        self.resolution_statistics["unresolved"] += 1
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
            self.resolution_statistics["group_cycles"] += 1
            return [f"{name} [group-cycle]"]

        lookup, ambiguous = self.lookup_address(name, scope)
        if lookup is None:
            return [f"{name} [ambiguous-scope]" if ambiguous else f"{name} [unresolved]"]

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
                    "layer": next((n.tag for n in reversed(self.ancestry(entry))
                                   if n.tag in ("pre-rulebase", "post-rulebase", "rulebase")), "unknown"),
                    "layer_order": len(self.security_rules) if elem.tag == "security" else (len(self.nat_rules) if elem.tag == "nat" else len(self.decryption_rules)),
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

    def discover_ipsec_tunnels(self):        for entry in self.root.findall(".//network/tunnel/ipsec/entry"):
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


REPORT_EVIDENCE_FIELDS = [
    "object", "scope", "source_zones", "source_objects", "resolved_sources",
    "destination_zones", "destination_objects", "resolved_destinations",
    "applications", "services", "evidence", "status", "confidence", "risk_score",
]


def consolidate_findings(findings):
    """Group equivalent rule findings; preserve each detection as a full evidence row."""
    rule_sections = {"Firewall Rules", "Decryption Rules", "NAT Rules"}
    groups = {}
    ordered = []
    for finding in findings:
        # Consolidate rule-level findings only. Non-rule findings remain separate
        # to avoid merging distinct VPN, management or platform objects.
        is_rule = finding.get("section") in rule_sections and bool(finding.get("object"))
        if is_rule:
            key = tuple(finding.get(field, "") for field in (
                "section", "title", "severity", "confidence", "status", "scope",
                "description", "remediation", "risk_score",
            ))
        else:
            key = ("SINGLE", finding.get("finding_id", ""))
        if key not in groups:
            group = dict(finding)
            group["affected_rules"] = []
            group["original_finding_ids"] = []
            group["affected_count"] = 0
            groups[key] = group
            ordered.append(group)
        group = groups[key]
        row = {field: finding.get(field, "") for field in REPORT_EVIDENCE_FIELDS}
        row["original_finding_id"] = finding.get("finding_id", "")
        group["affected_rules"].append(row)
        if finding.get("finding_id"):
            group["original_finding_ids"].append(finding["finding_id"])
        group["affected_count"] += 1

    for group in ordered:
        count = group["affected_count"]
        if count > 1:
            group["evidence"] = (
                f"{count} matching rule-level detections consolidated. "
                "Review the complete affected-rule evidence table for per-rule details."
            )
            group["object"] = f"{group.get('title', 'Finding')} ({count} affected)"
    return ordered


def evidence_rows(findings):
    """Flatten consolidated findings into one complete row per source finding."""
    rows = []
    for finding in findings:
        affected = finding.get("affected_rules") or []
        if not affected:
            affected = [{field: finding.get(field, "") for field in REPORT_EVIDENCE_FIELDS}]
        for row in affected:
            rows.append({
                "finding_id": finding.get("finding_id", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", ""),
                "section": finding.get("section", ""),
                "affected_count": finding.get("affected_count", 1),
                **row,
            })
    return rows


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def csv_fields():
    return [
        "finding_id",
        "severity", "confidence", "status", "section", "title", "object",
        "scope", "risk_score", "source_zones", "source_objects",
        "resolved_sources", "destination_zones", "destination_objects",
        "resolved_destinations", "applications", "services",
        "description", "evidence", "remediation", "affected_count", "original_finding_ids",
    ]


def write_csv(path, findings):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields(), extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = dict(finding)
            row["original_finding_ids"] = ";".join(finding.get("original_finding_ids", []))
            writer.writerow(row)


def write_evidence_csv(path, findings):
    fields = ["finding_id", "title", "severity", "section", "affected_count",
              "original_finding_id", *REPORT_EVIDENCE_FIELDS]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(evidence_rows(findings))


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

    def html_evidence_table(finding, esc):
        rows = evidence_rows([finding])
        if not rows:
            return ""
        columns = [
            ("Rule / Object [Original ID]", "object"), ("Scope", "scope"),
            ("Source IP / Object", "resolved_sources"),
            ("Destination IP / Object", "resolved_destinations"),
            ("Zones", "source_zones"), ("Destination Zones", "destination_zones"),
            ("Applications", "applications"), ("Services", "services"), ("Action / Evidence", "evidence"),
        ]
        head = "".join(f"<th>{esc(label)}</th>" for label, _ in columns)
        body = []
        for row in rows:
            cells = []
            for label, field in columns:
                value = row.get(field, "")
                if field == "object" and row.get("original_finding_id"):
                    value = f"{value} [{row.get('original_finding_id')}]"
                cells.append(f"<td>{esc(value)}</td>")
            body.append("<tr>" + "".join(cells) + "</tr>")
        return f'<h4>Affected rules ({len(rows)})</h4><table class="context-table"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>'

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
                f'<h3>{esc(x.get("title"))} <span class="finding-id">({int(x.get("affected_count",1))} affected)</span></h3></div>'
                f'<div class="confidence">{esc(x.get("confidence"))}</div></div>'
                f'<p class="description">{esc(x.get("description"))}</p>'
                '<div class="finding-grid"><div><h4>Evidence</h4>'
                f'<div class="evidence">{esc(x.get("evidence"))}</div></div>'
                '<div><h4>Remediation</h4>'
                f'<div class="remediation">{esc(x.get("remediation"))}</div></div></div>'
                '<details><summary>Technical context and affected rules</summary>'
                f'<table class="context-table">{"".join(context_rows)}</table>'
                f'{html_evidence_table(x, esc)}</details>'
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
    detected_count = int(meta.get("detected_finding_count", len(findings)) or 0)
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
<p>The assessment identified <strong>{len(findings)}</strong> consolidated finding groups covering <strong>{detected_count}</strong> original detection(s). <strong>{high_critical}</strong> groups are High/Critical priority, <strong>{confirmed}</strong> are confirmed by configuration evidence, and <strong>{review}</strong> require contextual validation.</p>
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
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, LongTable, TableStyle, PageBreak,
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
    detected_count = int(meta.get("detected_finding_count", len(findings)) or 0)

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
        canvas.line(18*mm, 13*mm, doc.pagesize[0]-18*mm, 13*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(palette["muted"])
        canvas.drawString(18*mm, 8*mm, f"H4wkEye v{VERSION} - Offline Configuration Security Scanner")
        canvas.drawRightString(doc.pagesize[0]-18*mm, 8*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(path), pagesize=landscape(A4), rightMargin=15*mm, leftMargin=15*mm,
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
            f"Overall assessment: {overall}. The assessment identified {len(findings)} consolidated finding groups "
            f"covering {detected_count} original detection(s). {high_critical} groups are High/Critical priority, "
            f"{confirmed} are confirmed by configuration "
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
                  P(f"{x.get('title','')} ({int(x.get('affected_count',1))} affected)", finding_title)]],
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
            # Keep each PDF table row shorter than a page. ReportLab cannot split
            # a single oversized table cell across pages, even in LongTable.
            # Preserve the full content; the JSON/HTML reports are unchanged.
            context_rows = []
            for k, v in context_fields:
                if v in (None, "", [], {}):
                    continue
                if isinstance(v, (list, tuple, set)):
                    parts = [str(item) for item in v]
                else:
                    parts = str(v).split(", ")
                chunks = []
                current = ""
                for part in parts:
                    # Bound both individual tokens and total paragraph length.
                    tokens = [part[i:i+160] for i in range(0, len(part), 160)] or [""]
                    for token in tokens:
                        candidate = (current + ", " + token) if current else token
                        if len(candidate) > 480 and current:
                            chunks.append(current)
                            current = token
                        else:
                            current = candidate
                if current:
                    chunks.append(current)
                for i, chunk in enumerate(chunks):
                    context_rows.append([P(k if i == 0 else f"{k} (cont.)", label), P(chunk, small)])
            if context_rows:
                ct = LongTable(context_rows, colWidths=[35*mm,130*mm], splitByRow=1)
                ct.setStyle(TableStyle([
                    ("GRID",(0,0),(-1,-1),0.25,palette["line"]),
                    ("BACKGROUND",(0,0),(0,-1),palette["panel"]),
                    ("VALIGN",(0,0),(-1,-1),"TOP"),
                    ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
                ]))
                block += [Paragraph("Technical Context", h2), ct]
            affected = x.get("affected_rules") or []
            if affected:
                block += [Paragraph(f"Affected Rules and Complete Technical Evidence ({len(affected)})", h2)]
                evidence_data = [[P("Rule / Object", label), P("Source IP/CIDR + context", label),
                                 P("Destination IP/CIDR + context", label), P("Application / Service", label),
                                 P("Scope", label), P("Technical Evidence", label)]]
                for row in affected:
                    src_parts = []
                    for caption, key in (("Resolved IP/CIDR", "resolved_sources"),
                                         ("Object", "source_objects"), ("Zone", "source_zones")):
                        if row.get(key):
                            src_parts.append(f"{caption}: {row.get(key)}")
                    dst_parts = []
                    for caption, key in (("Resolved IP/CIDR", "resolved_destinations"),
                                         ("Object", "destination_objects"), ("Zone", "destination_zones")):
                        if row.get(key):
                            dst_parts.append(f"{caption}: {row.get(key)}")
                    appsvc = " | ".join(f"{caption}: {row.get(key)}" for caption, key in
                                         (("Application", "applications"), ("Service", "services")) if row.get(key))
                    evidence_data.append([P(row.get("object", ""), small), P("\n".join(src_parts) or "Not specified", small),
                                         P("\n".join(dst_parts) or "Not specified", small), P(appsvc or "Not specified", small),
                                         P(row.get("scope", ""), small), P(row.get("evidence", ""), small)])
                ev_table = LongTable(evidence_data, colWidths=[31*mm, 51*mm, 51*mm, 43*mm, 36*mm, 52*mm],
                                     repeatRows=1, splitByRow=1, splitInRow=1)
                ev_table.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), palette["panel"]),
                    ("GRID", (0,0), (-1,-1), 0.3, palette["line"]),
                    ("VALIGN", (0,0), (-1,-1), "TOP"),
                    ("TOPPADDING", (0,0), (-1,-1), 4),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ]))
                block += [ev_table]
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


# Paths are structural only. Counting configured entries is different from
# counting parent containers, and no inventory-only data becomes a finding.
CONFIG_ENTRY_PATHS = {
    "interfaces": ("./devices/entry/network/interface//entry",),
    "zones": ("./devices/entry/vsys/entry/zone/entry",),
    "virtual_routers": ("./devices/entry/network/virtual-router/entry",),
    "ike_gateways": ("./devices/entry/network/ike/gateway/entry",),
    "ipsec_tunnels": ("./devices/entry/network/tunnel/ipsec/entry",),
    "globalprotect_portals": ("./devices/entry/network/global-protect/global-protect-portal/entry",),
    "globalprotect_gateways": ("./devices/entry/network/global-protect/global-protect-gateway/entry",),
    "authentication_profiles": ("./shared/authentication-profile/entry", "./devices/entry/vsys/entry/authentication-profile/entry"),
    "interface_management_profiles": ("./devices/entry/network/profiles/interface-management-profile/entry",),
    "log_forwarding_profiles": ("./shared/log-settings/profiles/entry", "./devices/entry/vsys/entry/log-settings/profiles/entry"),
}


def standalone_coverage_inventory(scanner):
    """Privacy-safe counts, not an effective configuration or assessment claim."""
    root = scanner.root
    panorama = bool(root.findall(".//device-group/entry") or
                    root.findall(".//device-groups/entry") or
                    root.findall(".//template/entry") or
                    root.findall(".//template-stack/entry"))
    result = {"schema_version": "1.0", "source_type": "panorama" if panorama else "standalone_or_other"}
    if panorama:
        result["note"] = "Standalone inventory not applied to Panorama; inherited/effective settings unresolved"
        return result
    counts = {}
    for category, paths in CONFIG_ENTRY_PATHS.items():
        # Some valid sections contain nested entries; these are structural counts,
        # not necessarily distinct configured interface instances.
        counts[category] = sum(len(root.findall(path)) for path in paths)
    local = {}
    for kind in ("security", "nat", "decryption"):
        local[kind] = len(root.findall(f"./devices/entry/vsys/entry/rulebase/{kind}/rules/entry"))
    unexpected = Counter()
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1] if isinstance(elem.tag, str) else ""
        if "redacted" in tag.lower():
            # Only generic category counts, never export actual unknown tag names.
            unexpected["redaction_like_element_names"] += 1
    result.update({
        "local_policy_entries": local,
        "configuration_entry_counts": counts,
        "deviceconfig_present": bool(root.findall("./devices/entry/deviceconfig")),
        "local_policy_status": "PRESENT" if any(local.values()) else "NO_LOCAL_RULES",
        "effective_policy_status": "NOT_DETERMINED",
        "structure_warnings": dict(unexpected),
        "limitations": [
            "Counts are structural and do not prove that a section was security-assessed.",
            "Absent local rules do not establish absence of Panorama-pushed rules.",
            "Container presence alone does not establish configured VPN or security objects.",
            "Device configuration and runtime/effective policy are not fully evaluated.",
        ],
    })
    return result


def detect_coverage(scanner, configuration_coverage=None):
    """Conservative coverage signal, not a claim that a device is secure."""
    root = scanner.root
    tag = str(root.tag).split("}")[-1]
    inventory = scanner.inventory
    assessed = sum(inventory.get(k, 0) for k in (
        "Security rules", "Decryption rules", "NAT rules", "IKE gateways",
        "IPsec tunnels", "GlobalProtect portals", "GlobalProtect gateways",
        "Interface management profiles", "Zone Protection profiles",
        "Authentication profiles"))
    panorama = bool(root.findall(".//device-group/entry") or
                    root.findall(".//device-groups/entry") or
                    root.findall(".//template/entry") or
                    root.findall(".//template-stack/entry"))
    if tag not in ("config", "response"):
        return "PARTIAL", "Unrecognized XML root; assessment coverage not verified"
    if panorama:
        return "PARTIAL", "Panorama detected; template inheritance and effective policy are not fully resolved"
    if assessed == 0:
        if scanner.findings:
            return "PARTIAL", ("No supported policy/VPN/profile objects discovered; "
                               "configuration-level findings exist, but assessment coverage is incomplete")
        return "PARTIAL", ("No supported assessable policy/VPN/profile objects discovered; "
                           "zero findings are inconclusive")
    policy_containers = any(e.tag in ("pre-rulebase", "post-rulebase", "rulebase") for e in root.iter())
    if policy_containers and inventory.get("Security rules", 0) == 0:
        return "PARTIAL", "Policy containers detected but no security rules parsed; effective policy not determined"
    return "COMPLETED", "Supported configuration sections assessed; not a security certification"


def panorama_diagnostics(scanner):
    """Inventory policy scope and hierarchy; never claim effective-policy resolution."""
    root = scanner.root
    scopes = Counter()
    raw = Counter()
    for node in root.iter():
        if node.tag not in ("security", "nat", "decryption"):
            continue
        rules = node.find("./rules")
        if rules is None:
            continue
        for entry in rules.findall("./entry"):
            ancestry = scanner.ancestry(entry)
            layer = next((n.tag for n in reversed(ancestry)
                          if n.tag in ("pre-rulebase", "post-rulebase", "rulebase")), "other")
            scope = scanner.scope(entry)
            raw[node.tag] += 1
            scopes[(node.tag, layer, scope)] += 1

    parsed = {"security": len(scanner.security_rules),
              "nat": len(scanner.nat_rules),
              "decryption": len(scanner.decryption_rules)}
    group_entries = root.findall("./devices/entry/device-group/entry")
    group_entries += root.findall("./device-group/entry")
    groups = []
    for e in group_entries:
        groups.append({"name": e.get("name", ""),
                       "parent": text_of(e, "./parent-dg") or None,
                       "devices": len(e.findall("./devices/entry"))})
    group_names = {g["name"] for g in groups}
    missing_parents = sorted({g["parent"] for g in groups
                              if g["parent"] and g["parent"] not in group_names})
    templates = root.findall("./devices/entry/template/entry")
    templates += root.findall("./template/entry")
    stacks = root.findall("./devices/entry/template-stack/entry")
    stacks += root.findall("./template-stack/entry")
    stack_info = [{"name": e.get("name", ""),
                   "templates": members(e, "./templates"),
                   "devices": len(e.findall("./devices/entry"))} for e in stacks]
    return {
        "method": "raw XML scope inventory; NOT effective-policy evaluation",
        "raw_policy_entries": dict(raw),
        "scanner_parsed_entries": parsed,
        "policy_count_mismatch": {k: {"xml": raw[k], "parsed": parsed[k]}
                                  for k in parsed if raw[k] != parsed[k]},
        "policy_scopes": [{"type": kind, "layer": layer, "scope": scope, "count": count}
                          for (kind, layer, scope), count in sorted(scopes.items())],
        "device_groups": groups,
        "missing_parent_device_groups": missing_parents,
        "templates": [e.get("name", "") for e in templates],
        "template_stacks": stack_info,
        "limitations": [
            "Parent device-group rules and shared objects are not merged into an effective per-device rulebase.",
            "Template and template-stack settings are inventoried, not overlaid with device-local settings.",
            "Object lookup may fall back to unrelated scopes; contextual rule findings need validation.",
            "Local firewall overrides and runtime state may be absent from the Panorama export.",
            "Counts represent XML entries and may include repeated or non-effective rules."
        ],
    }



def panorama_inheritance_preview(scanner):
    """Privacy-safe device-group policy composition diagnostics.

    Produces *counts* in pre/leaf/post evaluation order, not effective firewall
    policy or findings. Does not expand templates, targets or local overrides.
    """
    root = scanner.root
    entries = (root.findall("./devices/entry/device-group/entry") +
               root.findall("./device-group/entry"))
    shared = root.find("./shared")
    names = [e.get("name", "") for e in entries]
    from collections import Counter as _Counter
    counts = _Counter(names)
    aliases = {name: f"DG-{i:03d}" for i, name in enumerate(sorted(set(names)), 1) if name}
    by_name = {e.get("name"): e for e in entries if e.get("name")}
    problems = []
    if any(n != 1 for n in counts.values()):
        problems.append("DUPLICATE_DEVICE_GROUP_IDENTITY")
    if any(not n for n in names):
        problems.append("MISSING_DEVICE_GROUP_IDENTITY")
    parents = {name: text_of(e, "./parent-dg").strip() for name, e in by_name.items()}
    if any(p and p not in by_name for p in parents.values()):
        problems.append("MISSING_PARENT_DEVICE_GROUP")
    def rule_counts(node, layer):
        if node is None:
            return {k: 0 for k in ("security", "nat", "decryption")}
        return {k: len(node.findall(f"./{layer}/{k}/rules/entry"))
                for k in ("security", "nat", "decryption")}
    shared_pre = rule_counts(shared, "pre-rulebase")
    shared_post = rule_counts(shared, "post-rulebase")
    records = []
    for name in sorted(by_name):
        chain = []
        visited = set()
        cur = name
        issue = None
        while cur:
            if cur in visited:
                issue = "PARENT_CYCLE"
                break
            if cur not in by_name:
                issue = "MISSING_PARENT_DEVICE_GROUP"
                break
            visited.add(cur)
            chain.append(cur)
            cur = parents[cur]
        chain.reverse()
        if issue:
            problems.append(issue)
        layers = []
        layers.append(("shared_pre", shared_pre))
        for ancestor in chain:
            layers.append(("dg_pre", rule_counts(by_name[ancestor], "pre-rulebase")))
        for ancestor in reversed(chain):
            layers.append(("dg_post", rule_counts(by_name[ancestor], "post-rulebase")))
        layers.append(("shared_post", shared_post))
        totals = {kind: sum(c[kind] for _, c in layers) for kind in ("security", "nat", "decryption")}
        records.append({
            "device_group_id": aliases.get(name, "UNRESOLVED-DG"),
            "ancestor_chain": [aliases.get(n, "UNRESOLVED-DG") for n in chain],
            "composition": [{"source": source, "counts": value} for source, value in layers],
            "candidate_policy_counts": totals,
            "status": "BLOCKED" if issue or counts[name] != 1 else "DIAGNOSTIC_ONLY",
            "blocking_reason": issue or ("DUPLICATE_DEVICE_GROUP_IDENTITY" if counts[name] != 1 else None),
        })
    return {
        "schema_version": "0.1",
        "mode": "candidate_policy_count_composition_only",
        "status": "PARTIAL" if problems else "DIAGNOSTIC_ONLY",
        "problems": sorted(set(problems)),
        "device_group_count": len(entries),
        "shared_pre_counts": shared_pre,
        "shared_post_counts": shared_post,
        "device_groups": records,
        "limitations": [
            "Counts are not effective firewall policy or vulnerability findings.",
            "Device targets, disabled rules, rule overrides, and runtime state are not resolved.",
            "Template stacks, device-local rules, and pushed configuration are not merged.",
            "Repeated ancestor policies in different device-group views are expected.",
        ],
    }


def classify_panorama_rule_target(rule):
    """Classify target XML conservatively; never infer device applicability.

    A missing target or a target with only <negate>no</negate> has no
    explicit device restriction. A negated target without devices is
    ambiguous and stays UNKNOWN. Validate known device/vsys container
    shapes rather than treating arbitrary children as device selectors.
    """
    target = rule.find("./target")
    if target is None:
        return "NO_EXPLICIT_TARGET"
    if (target.text or "").strip():
        return "UNKNOWN_TARGET_SHAPE"
    children = list(target)
    if not children:
        return "NO_EXPLICIT_TARGET"
    if any(child.tag not in ("negate", "devices") for child in children):
        return "UNKNOWN_TARGET_SHAPE"
    if sum(child.tag == "negate" for child in children) > 1 or sum(child.tag == "devices" for child in children) > 1:
        return "UNKNOWN_TARGET_SHAPE"
    negate_node = target.find("./negate")
    negate = (negate_node.text or "").strip().lower() if negate_node is not None else "no"
    if negate not in ("yes", "no") or (negate_node is not None and len(negate_node)):
        return "UNKNOWN_TARGET_SHAPE"
    devices = target.find("./devices")
    if devices is None:
        return "NO_EXPLICIT_TARGET" if negate == "no" else "UNKNOWN_TARGET_SHAPE"
    if (devices.text or "").strip():
        return "UNKNOWN_TARGET_SHAPE"
    entries = list(devices)
    if not entries:
        return "NO_EXPLICIT_TARGET" if negate == "no" else "UNKNOWN_TARGET_SHAPE"
    for entry in entries:
        if entry.tag != "entry" or not (entry.get("name") or "").strip():
            return "UNKNOWN_TARGET_SHAPE"
        if (entry.text or "").strip() or any(k != "name" for k in entry.attrib):
            return "UNKNOWN_TARGET_SHAPE"
        if any(child.tag != "vsys" for child in entry):
            return "UNKNOWN_TARGET_SHAPE"
        if len(entry.findall("./vsys")) > 1:
            return "UNKNOWN_TARGET_SHAPE"
        vsys = entry.find("./vsys")
        if vsys is not None:
            if (vsys.text or "").strip() or not len(vsys):
                return "UNKNOWN_TARGET_SHAPE"
            if any(v.tag != "entry" or not (v.get("name") or "").strip() or len(v) or (v.text or "").strip() for v in vsys):
                return "UNKNOWN_TARGET_SHAPE"
    return "EXPLICIT_TARGET_EXCLUSION" if negate == "yes" else "EXPLICIT_TARGET_INCLUSION"


def panorama_targeting_preview(scanner):
    """Aggregate, privacy-safe target/disabled diagnostics, not effective policy.

    Traverses raw shared and device-group rule containers once, avoiding
    counting inherited rules repeatedly. No device serials or rule names leave
    the scanner. Unknown target shapes remain unknown, never assumed allowed.
    """
    from collections import Counter as _Counter
    root = scanner.root
    groups = root.findall("./devices/entry/device-group/entry") + root.findall("./device-group/entry")
    scopes = [("shared", root.find("./shared"))] + [("device_group", e) for e in groups]
    kinds = ("security", "nat", "decryption")
    tally = _Counter()
    by_type = {k: _Counter() for k in kinds}
    by_layer = {k: _Counter() for k in ("pre-rulebase", "post-rulebase")}
    sample_limit = 0  # No names, identifiers, or rule contents in diagnostics.
    for scope, node in scopes:
        if node is None:
            continue
        for layer in ("pre-rulebase", "post-rulebase"):
            for kind in kinds:
                for rule in node.findall(f"./{layer}/{kind}/rules/entry"):
                    disabled = text_of(rule, "./disabled").lower()
                    if disabled == "yes":
                        state = "DISABLED"
                    elif disabled in ("", "no"):
                        state = "ENABLED_OR_UNSPECIFIED"
                    else:
                        state = "UNKNOWN_ENABLEMENT"
                    target_state = classify_panorama_rule_target(rule)
                    tally["total_rules"] += 1
                    tally["enablement:" + state] += 1
                    tally["target:" + target_state] += 1
                    by_type[kind]["total"] += 1
                    by_type[kind]["target:" + target_state] += 1
                    by_layer[layer][kind] += 1
    return {
        "schema_version": "0.3",
        "status": "DIAGNOSTIC_ONLY",
        "mode": "raw_rule_target_and_enablement_inventory",
        "raw_rules_visited": tally["total_rules"],
        "enablement": {k.removeprefix("enablement:"): v for k, v in sorted(tally.items()) if k.startswith("enablement:")},
        "targeting": {k.removeprefix("target:"): v for k, v in sorted(tally.items()) if k.startswith("target:")},
        "by_type": {k: dict(v) for k, v in by_type.items()},
        "by_layer": {k: dict(v) for k, v in by_layer.items()},
        "effective_device_applicability": "NOT_EVALUATED",
        "limitations": [
            "No per-firewall applicability claim is made: device membership, serial/vsys mapping, and target semantics are not resolved.",
            "Explicit targets are classified structurally, not interpreted as effective inclusion or exclusion.",
            "Inherited views are not duplicated in these raw-rule counts.",
            "Existing vulnerability detection and report findings are unchanged.",
        ],
    }



def panorama_membership_preview(scanner):
    """Inventory Panorama DG device/VSYS assignments without exposing identities.

    A device-group assignment is not proof of effective policy deployment.
    Missing/ambiguous assignments remain unresolved. No rule findings change.
    """
    from collections import Counter as _Counter, defaultdict as _defaultdict
    root = scanner.root
    groups = (root.findall("./devices/entry/device-group/entry") +
              root.findall("./device-group/entry"))
    names = [g.get("name", "").strip() for g in groups]
    counts = _Counter(names)
    aliases = {name: f"DG-{i:03d}" for i, name in enumerate(sorted(set(names)), 1) if name}
    memberships = _defaultdict(list)
    issues = _Counter()
    rows = []
    for group in groups:
        name = (group.get("name") or "").strip()
        members = group.findall("./devices/entry")
        group_devices = set()
        vsys_assignments = 0
        for member in members:
            serial = (member.get("name") or "").strip()
            if not serial:
                issues["MISSING_DEVICE_IDENTITY"] += 1
                continue
            if serial in group_devices:
                issues["DUPLICATE_DEVICE_IN_GROUP"] += 1
            group_devices.add(serial)
            vsys = member.find("./vsys")
            if vsys is None:
                membership_type = "DEVICE_ONLY"
                vsys_values = ()
            else:
                vsys_entries = vsys.findall("./entry")
                vsys_values = tuple(v.get("name", "").strip() for v in vsys_entries)
                if not vsys_values or any(not v for v in vsys_values) or len(vsys_values) != len(set(vsys_values)) or len(list(vsys)) != len(vsys_entries):
                    issues["UNRESOLVED_VSYS_SHAPE"] += 1
                    membership_type = "UNKNOWN_VSYS"
                else:
                    membership_type = "EXPLICIT_VSYS"
                    vsys_assignments += len(vsys_values)
            memberships[serial].append((name, membership_type, vsys_values))
        rows.append({
            "device_group_id": aliases.get(name, "UNRESOLVED-DG"),
            "assigned_device_entries": len(members),
            "unique_device_identities": len(group_devices),
            "explicit_vsys_assignments": vsys_assignments,
            "status": "UNRESOLVED" if not name or counts[name] != 1 else "INVENTORIED",
        })
    if any(not n for n in names):
        issues["MISSING_DEVICE_GROUP_IDENTITY"] += 1
    if any(v > 1 for v in counts.values()):
        issues["DUPLICATE_DEVICE_GROUP_IDENTITY"] += 1
    for serial, assignments in memberships.items():
        distinct_groups = {g for g, _, _ in assignments}
        if len(distinct_groups) > 1:
            issues["DEVICE_IN_MULTIPLE_GROUPS"] += 1
    assignment_kinds = _Counter(t for a in memberships.values() for _, t, _ in a)
    return {
        "schema_version": "0.1",
        "status": "PARTIAL" if issues else "DIAGNOSTIC_ONLY",
        "mode": "device_group_assignment_inventory_only",
        "device_group_count": len(groups),
        "unique_assigned_devices": len(memberships),
        "total_device_assignment_entries": sum(r["assigned_device_entries"] for r in rows),
        "assignment_shapes": dict(sorted(assignment_kinds.items())),
        "issues": dict(sorted(issues.items())),
        "device_groups": rows,
        "effective_device_applicability": "NOT_EVALUATED",
        "limitations": [
            "Device group assignments do not prove policies were pushed or are effective.",
            "Device-local overrides, templates, operational state, and target-device resolution are not evaluated.",
            "Device identifiers and VSYS names are not exported.",
            "Device assignment counts do not deduplicate inherited candidate policies.",
        ],
    }



def panorama_candidate_mapping_preview(scanner):
    """Privacy-safe VSYS-aware candidate counts; never asserts deployed policy.

    Assignments with no VSYS are device-scoped and are NOT interpreted as vsys1.
    A candidate is a rule present in the composed DG rulebase, regardless of
    target restrictions. Explicit targeting and malformed enablement remain
    unresolved instead of being counted as confirmed applicable.
    """
    from collections import Counter as _Counter, defaultdict as _defaultdict
    root = scanner.root
    groups = root.findall("./devices/entry/device-group/entry") + root.findall("./device-group/entry")
    names = [(g.get("name") or "").strip() for g in groups]
    name_counts = _Counter(names)
    by_name = {n: g for n, g in zip(names, groups) if n}
    aliases = {n: f"DG-{i:03d}" for i, n in enumerate(sorted(set(names)), 1) if n}
    kinds = ("security", "nat", "decryption")
    shared = root.find("./shared")
    issues = _Counter()
    records = []
    # Do not export the private mapping or actual device/VSYS identities.
    assignments = _defaultdict(set)
    for group, name in zip(groups, names):
        if not name or name_counts[name] != 1:
            issues["UNRESOLVED_DEVICE_GROUP_IDENTITY"] += 1
            continue
        for member in group.findall("./devices/entry"):
            serial = (member.get("name") or "").strip()
            if not serial:
                issues["MISSING_DEVICE_IDENTITY"] += 1
                continue
            vsys = member.find("./vsys")
            if vsys is None:
                assignments[(serial, None)].add(name)
                continue
            entries = vsys.findall("./entry")
            if not entries or len(entries) != len(list(vsys)) or (vsys.text or "").strip():
                issues["UNRESOLVED_VSYS_SHAPE"] += 1
                continue
            values = [(e.get("name") or "").strip() for e in entries]
            if not all(values) or len(values) != len(set(values)) or any(len(e) for e in entries):
                issues["UNRESOLVED_VSYS_SHAPE"] += 1
                continue
            for v in values:
                assignments[(serial, v)].add(name)
    # Device-only plus VSYS-specific memberships on the same device require
    # additional context, and must not be silently collapsed.
    devices_with_vsys = {serial for serial, vsys in assignments if vsys is not None}
    for serial, vsys in assignments:
        if vsys is None and serial in devices_with_vsys:
            issues["DEVICE_ONLY_OVERLAPS_EXPLICIT_VSYS"] += 1
    def chain_for(name):
        chain, seen = [], set()
        current = name
        while current:
            if current in seen:
                return None, "PARENT_CYCLE"
            if current not in by_name or name_counts[current] != 1:
                return None, "MISSING_OR_DUPLICATE_PARENT"
            seen.add(current)
            chain.append(current)
            current = (by_name[current].findtext("./parent-dg") or "").strip()
        return list(reversed(chain)), None
    def source_nodes(chain):
        return ([('shared_pre', shared, 'pre-rulebase')]
                + [('dg_pre', by_name[n], 'pre-rulebase') for n in chain]
                + [('dg_post', by_name[n], 'post-rulebase') for n in reversed(chain)]
                + [('shared_post', shared, 'post-rulebase')])
    # Cache per-DG composition, avoiding repeated XML traversal for multiple VSYS.
    cache = {}
    def summarize(name):
        if name in cache:
            return cache[name]
        chain, error = chain_for(name)
        if error:
            cache[name] = (None, error)
            return cache[name]
        counts = {kind: _Counter() for kind in kinds}
        ordered_sources = []
        for source, node, layer in source_nodes(chain):
            source_counts = {kind: 0 for kind in kinds}
            if node is not None:
                for kind in kinds:
                    for rule in node.findall(f'./{layer}/{kind}/rules/entry'):
                        source_counts[kind] += 1                        counts[kind]['candidate'] += 1
                        disabled = (rule.findtext('./disabled') or '').strip().lower()
                        if disabled == 'yes':
                            counts[kind]['disabled'] += 1
                        elif disabled in ('', 'no'):
                            counts[kind]['enabled_or_unspecified'] += 1
                        else:
                            counts[kind]['unknown_enablement'] += 1
                        target = classify_panorama_rule_target(rule)
                        if target == 'NO_EXPLICIT_TARGET':
                            counts[kind]['no_explicit_target'] += 1
                        elif target == 'UNKNOWN_TARGET_SHAPE':
                            counts[kind]['unknown_target_shape'] += 1
                        else:
                            counts[kind]['explicit_target_requires_resolution'] += 1
            ordered_sources.append({'source': source, 'counts': source_counts})
        cache[name] = ({'ancestor_chain': [aliases[n] for n in chain],
                        'ordered_sources': ordered_sources,
                        'policy_counts': {k: dict(counts[k]) for k in kinds}}, None)
        return cache[name]
    for idx, ((serial, vsys), groups_for_assignment) in enumerate(sorted(assignments.items()), 1):
        label = f'ASSIGNMENT-{idx:03d}'
        if len(groups_for_assignment) != 1:
            issues['CONFLICTING_VSYS_ASSIGNMENT'] += 1
            records.append({'assignment_id': label, 'assignment_type': 'DEVICE_ONLY' if vsys is None else 'EXPLICIT_VSYS',
                            'status': 'BLOCKED', 'reason': 'CONFLICTING_VSYS_ASSIGNMENT',
                            'device_group_ids': [aliases[g] for g in sorted(groups_for_assignment)]})
            continue
        name = next(iter(groups_for_assignment))
        composition, error = summarize(name)
        records.append({'assignment_id': label,
                        'assignment_type': 'DEVICE_ONLY' if vsys is None else 'EXPLICIT_VSYS',
                        'device_group_id': aliases[name],
                        'status': 'BLOCKED' if error else 'CANDIDATE_ONLY',
                        'reason': error,
                        **(composition or {})})
        if error:
            issues[error] += 1
    # Avoid exposing serials even indirectly through shared pseudonyms.
    return {'schema_version': '0.1', 'status': 'PARTIAL' if issues else 'DIAGNOSTIC_ONLY',
            'mode': 'vsys_aware_candidate_policy_composition',
            'assignment_count': len(records),
            'assignment_types': dict(sorted(_Counter(r['assignment_type'] for r in records).items())),
            'issues': dict(sorted(issues.items())),
            'assignments': records,
            'effective_device_applicability': 'NOT_EVALUATED',
            'limitations': [
                'Candidate counts do not establish installed or effective firewall policy.',
                'Explicit target inclusion/exclusion is inventoried, not resolved for device/VSYS.',
                'Device-only assignments are not assumed to be vsys1.',
                'Template stacks, local overrides, runtime state and pushed configuration are not merged.',
                'Inherited rules may be counted in multiple assignment views; raw inventory is unchanged.',
                'Device and VSYS identities are not exported.'
            ]}



def panorama_applicability_preview(scanner):
    """Conservative assignment-level targeting diagnostics, NOT effective policy.

    Resolves only structurally valid explicit target selectors. Device-only
    assignments cannot establish VSYS-specific selector matches. Policy identity
    uses private XML scope, layer and position, never customer rule names.
    """
    from collections import Counter as _Counter, defaultdict as _defaultdict
    root = scanner.root
    groups = root.findall('./devices/entry/device-group/entry') + root.findall('./device-group/entry')
    names = [(g.get('name') or '').strip() for g in groups]
    duplicates = _Counter(names)
    by_name = {n: g for n, g in zip(names, groups) if n and duplicates[n] == 1}
    aliases = {n: f'DG-{i:03d}' for i, n in enumerate(sorted(set(names)), 1) if n}
    kinds = ('security', 'nat', 'decryption')
    issues = _Counter()
    memberships = _defaultdict(set)
    for name, group in zip(names, groups):
        if name not in by_name:
            issues['UNRESOLVED_DEVICE_GROUP_IDENTITY'] += 1
            continue
        for member in group.findall('./devices/entry'):
            serial = (member.get('name') or '').strip()
            if not serial:
                issues['MISSING_DEVICE_IDENTITY'] += 1
                continue
            vsys = member.find('./vsys')
            if vsys is None:
                memberships[(serial, None)].add(name)
                continue
            entries = list(vsys)
            values = [(e.get('name') or '').strip() for e in entries]
            if (not entries or any(e.tag != 'entry' or len(e) or not v for e, v in zip(entries, values))
                    or len(values) != len(set(values)) or (vsys.text or '').strip()):
                issues['UNRESOLVED_VSYS_SHAPE'] += 1
                continue
            for v in values:
                memberships[(serial, v)].add(name)
    devices_with_vsys = {d for d, v in memberships if v is not None}
    for device, vsys in memberships:
        if vsys is None and device in devices_with_vsys:
            issues['DEVICE_ONLY_OVERLAPS_EXPLICIT_VSYS'] += 1

    def chain(name):
        result, visited = [], set()
        while name:
            if name in visited:
                return None, 'PARENT_CYCLE'
            if name not in by_name:
                return None, 'MISSING_OR_DUPLICATE_PARENT'
            visited.add(name)
            result.append(name)
            name = (by_name[name].findtext('./parent-dg') or '').strip()
        return list(reversed(result)), None

    # Cache rule objects per device group: a rule may be referenced by many
    # assignments, but each source occurrence has one distinct internal key.
    rule_cache = {}
    def rules_for(name):
        if name in rule_cache:
            return rule_cache[name]
        ancestors, error = chain(name)
        if error:
            rule_cache[name] = (None, error)
            return rule_cache[name]
        sources = [('shared_pre', 'shared', root.find('./shared'), 'pre-rulebase')]
        sources += [('dg_pre', n, by_name[n], 'pre-rulebase') for n in ancestors]
        sources += [('dg_post', n, by_name[n], 'post-rulebase') for n in reversed(ancestors)]
        sources += [('shared_post', 'shared', root.find('./shared'), 'post-rulebase')]
        rows = []
        for source, scope, node, layer in sources:
            if node is None:
                continue
            for kind in kinds:
                for index, rule in enumerate(node.findall(f'./{layer}/{kind}/rules/entry')):
                    enable = (rule.findtext('./disabled') or '').strip().lower()
                    enablement = 'DISABLED' if enable == 'yes' else ('ENABLED_OR_UNSPECIFIED' if enable in ('', 'no') else 'UNKNOWN_ENABLEMENT')
                    shape = classify_panorama_rule_target(rule)
                    target = rule.find('./target')
                    negate = (target.findtext('./negate') or 'no').strip().lower() == 'yes' if target is not None else False
                    selectors = []
                    if shape in ('EXPLICIT_TARGET_INCLUSION', 'EXPLICIT_TARGET_EXCLUSION'):
                        for device in target.findall('./devices/entry'):
                            vsys = device.find('./vsys')
                            selectors.append((device.get('name'), None if vsys is None else frozenset(v.get('name') for v in vsys.findall('./entry'))))
                    # Identity remains private; only aggregate counts are exported.
                    key = (scope, layer, kind, index)
                    rows.append((key, kind, enablement, shape, negate, selectors))
        rule_cache[name] = (rows, None)
        return rule_cache[name]

    def targeting(shape, negate, selectors, serial, vsys):
        if shape == 'NO_EXPLICIT_TARGET':
            return 'NO_EXPLICIT_TARGET'
        if shape == 'UNKNOWN_TARGET_SHAPE':
            return 'UNRESOLVED_TARGET'
        # A device-wide selector is resolvable for both assignment types.
        # A VSYS-scoped selector is unresolved for a device-only assignment
        # when that device matches a VSYS-scoped target entry.
        device_matches = [(v is None, v) for d, v in selectors if d == serial]
        if vsys is None and any(not wide for wide, _ in device_matches):
            return 'UNRESOLVED_TARGET'
        matched = any(wide or (vsys is not None and vsys in values)
                      for wide, values in device_matches)
        allowed = not matched if negate else matched
        return 'TARGET_ELIGIBLE' if allowed else 'TARGET_EXCLUDED'

    results = []
    all_keys = set()
    reference_count = 0
    totals = {k: _Counter() for k in kinds}
    for index, ((serial, vsys), group_set) in enumerate(sorted(memberships.items()), 1):
        record = {'assignment_id': f'ASSIGNMENT-{index:03d}',
                  'assignment_type': 'DEVICE_ONLY' if vsys is None else 'EXPLICIT_VSYS'}
        if len(group_set) != 1:
            issues['CONFLICTING_VSYS_ASSIGNMENT'] += 1
            record.update(status='BLOCKED', reason='CONFLICTING_VSYS_ASSIGNMENT')
            results.append(record)
            continue
        name = next(iter(group_set))
        record['device_group_id'] = aliases[name]
        rules, error = rules_for(name)
        if error:
            issues[error] += 1
            record.update(status='BLOCKED', reason=error)
            results.append(record)
            continue
        per_type = {k: _Counter() for k in kinds}
        seen_in_assignment = set()
        for key, kind, enablement, shape, negate, selectors in rules:
            if key in seen_in_assignment:
                issues['DUPLICATE_POLICY_SOURCE_WITHIN_ASSIGNMENT'] += 1
                continue
            seen_in_assignment.add(key)
            all_keys.add(key)
            reference_count += 1
            c = per_type[kind]
            c['candidate'] += 1
            c[enablement.lower()] += 1
            target_state = targeting(shape, negate, selectors, serial, vsys)
            c[target_state.lower()] += 1
            if enablement == 'DISABLED':
                c['disabled_not_eligible'] += 1
            elif enablement == 'UNKNOWN_ENABLEMENT':
                c['unresolved_applicability'] += 1
            elif target_state == 'TARGET_EXCLUDED':
                c['target_excluded_enabled'] += 1
            elif target_state == 'UNRESOLVED_TARGET':
                c['unresolved_applicability'] += 1
            else:
                c['configuration_eligible_candidate'] += 1
        record.update(status='CANDIDATE_ONLY', policy_counts={k: dict(per_type[k]) for k in kinds})
        results.append(record)
        for kind in kinds:
            totals[kind].update(per_type[kind])
    return {
        'schema_version': '0.1', 'status': 'PARTIAL' if issues else 'DIAGNOSTIC_ONLY',
        'mode': 'conservative_target_and_enablement_candidate_diagnostics',
        'assignment_count': len(results), 'issues': dict(sorted(issues.items())),
        'unique_policy_source_occurrences_referenced': len(all_keys),
        'candidate_policy_references': reference_count,
        'by_type': {k: dict(totals[k]) for k in kinds},
        'assignments': results,
        'effective_device_applicability': 'NOT_EVALUATED',
        'limitations': [
            'Configuration-eligible candidates are not confirmed installed or enforced policies.',
            'Target selectors are interpreted only for supported XML shapes; ambiguous device-only VSYS matches remain unresolved.',
            'Policy identity is XML source occurrence, not semantic rule equivalence or deployed rule identity.',
            'Unique source occurrences referenced are not the full raw Panorama policy inventory.',
            'Local rules, overrides, template stacks, push status and runtime state are not merged.',
            'No customer serial, VSYS or rule name is exported.'
        ]
    }

def panorama_reconciliation_preview(candidate, applicability, raw_policy_entries=None):
    """Preview 7: privacy-safe accounting audit of candidate versus applicability.

    Operates solely on diagnostic aggregates, never on raw device identities.
    A clean audit does not establish pushed configuration or enforcement.
    """
    from collections import Counter as _Counter
    kinds = ('security', 'nat', 'decryption')
    issues = _Counter()
    candidate = candidate or {}
    applicability = applicability or {}
    raw = raw_policy_entries or {}
    c_rows = {a.get('assignment_id'): a for a in candidate.get('assignments', [])}
    a_rows = {a.get('assignment_id'): a for a in applicability.get('assignments', [])}
    if len(c_rows) != len(candidate.get('assignments', [])) or len(a_rows) != len(applicability.get('assignments', [])):
        issues['DUPLICATE_ASSIGNMENT_ID'] += 1
    if set(c_rows) != set(a_rows):
        issues['ASSIGNMENT_SET_MISMATCH'] += len(set(c_rows) ^ set(a_rows))
    per_assignment = []
    totals = {kind: _Counter() for kind in kinds}
    targeting = _Counter()
    enablement = _Counter()
    blocked = 0
    for aid in sorted(set(c_rows) | set(a_rows)):
        c, a = c_rows.get(aid, {}), a_rows.get(aid, {})
        if c.get('status') != 'CANDIDATE_ONLY' or a.get('status') != 'CANDIDATE_ONLY':
            blocked += 1
            per_assignment.append({'assignment_id': aid, 'status': 'BLOCKED_OR_UNRESOLVED'})
            continue
        if c.get('assignment_type') != a.get('assignment_type') or c.get('device_group_id') != a.get('device_group_id'):
            issues['ASSIGNMENT_METADATA_MISMATCH'] += 1
        rec = {'assignment_id': aid, 'assignment_type': a.get('assignment_type'),
               'device_group_id': a.get('device_group_id'), 'status': 'RECONCILED', 'by_type': {}}
        for kind in kinds:
            old = c.get('policy_counts', {}).get(kind, {})
            new = a.get('policy_counts', {}).get(kind, {})
            n = int(new.get('candidate', 0))
            if int(old.get('candidate', 0)) != n:
                issues['CANDIDATE_COUNT_MISMATCH'] += 1
                rec['status'] = 'MISMATCH'
            disabled = int(new.get('disabled', 0))
            enabled = int(new.get('enabled_or_unspecified', 0))
            unknown = int(new.get('unknown_enablement', 0))
            if n != disabled + enabled + unknown:
                issues['ENABLEMENT_PARTITION_MISMATCH'] += 1
                rec['status'] = 'MISMATCH'
            for field in ('disabled', 'enabled_or_unspecified', 'unknown_enablement'):
                if int(old.get(field, 0)) != int(new.get(field, 0)):
                    issues['ENABLEMENT_COUNT_MISMATCH'] += 1
                    rec['status'] = 'MISMATCH'
            no_target = int(new.get('no_explicit_target', 0))
            eligible_target = int(new.get('target_eligible', 0))
            excluded_target = int(new.get('target_excluded', 0))
            unresolved_target = int(new.get('unresolved_target', 0))
            if n != no_target + eligible_target + excluded_target + unresolved_target:
                issues['TARGET_PARTITION_MISMATCH'] += 1
                rec['status'] = 'MISMATCH'
            eligible = int(new.get('configuration_eligible_candidate', 0))
            excluded_enabled = int(new.get('target_excluded_enabled', 0))
            unresolved = int(new.get('unresolved_applicability', 0))
            disabled_not = int(new.get('disabled_not_eligible', 0))
            if n != eligible + excluded_enabled + unresolved + disabled_not:
                issues['ELIGIBILITY_PARTITION_MISMATCH'] += 1
                rec['status'] = 'MISMATCH'
            fields = ('candidate', 'disabled', 'enabled_or_unspecified', 'unknown_enablement',
                      'no_explicit_target', 'target_eligible', 'target_excluded', 'unresolved_target',
                      'configuration_eligible_candidate', 'target_excluded_enabled',
                      'unresolved_applicability', 'disabled_not_eligible')
            rec['by_type'][kind] = {key: int(new.get(key, 0)) for key in fields}
            totals[kind].update(rec['by_type'][kind])
            targeting['no_explicit_target'] += no_target
            targeting['explicit_target_eligible'] += eligible_target
            targeting['explicit_target_excluded'] += excluded_target
            targeting['unresolved_target'] += unresolved_target
            enablement['disabled'] += disabled
            enablement['enabled_or_unspecified'] += enabled
            enablement['unknown_enablement'] += unknown
        per_assignment.append(rec)
    reference_total = sum(counter.get('candidate', 0) for counter in totals.values())
    # Compare independently aggregated Preview 6 totals.
    if reference_total != applicability.get('candidate_policy_references', 0):
        issues['REFERENCE_TOTAL_MISMATCH'] += 1
    for kind in kinds:
        for key, value in applicability.get('by_type', {}).get(kind, {}).items():
            if totals[kind].get(key, 0) != value:
                issues['AGGREGATE_FIELD_MISMATCH'] += 1
    unique = int(applicability.get('unique_policy_source_occurrences_referenced', 0))
    raw_total = sum(int(raw.get(kind, 0)) for kind in kinds)
    if raw_total and unique > raw_total:
        issues['UNIQUE_SOURCE_EXCEEDS_RAW_INVENTORY'] += 1
    if unique > reference_total:
        issues['UNIQUE_SOURCE_EXCEEDS_REFERENCES'] += 1
    if candidate.get('issues') or applicability.get('issues'):
        issues['UPSTREAM_MAPPING_ISSUES'] += 1
    return {
        'schema_version': '0.1',
        'status': 'PARTIAL' if issues or blocked else 'DIAGNOSTIC_ONLY',
        'mode': 'candidate_accounting_and_targeting_coverage_audit',
        'assignment_count': len(per_assignment), 'reconciled_assignments': sum(r['status'] == 'RECONCILED' for r in per_assignment),
        'blocked_or_unresolved_assignments': blocked,
        'issues': dict(sorted(issues.items())),
        'raw_policy_entries': raw_total if raw else None,
        'unique_source_occurrences_referenced': unique,
        'candidate_policy_references': reference_total,
        'reused_assignment_references': reference_total - unique,
        'targeting_coverage': dict(sorted(targeting.items())),
        'enablement_coverage': dict(sorted(enablement.items())),
        'by_type': {k: dict(totals[k]) for k in kinds},
        'assignments': per_assignment,
        'effective_device_applicability': 'NOT_EVALUATED',
        'limitations': [
            'Diagnostic arithmetic and source identity do not establish effective or installed policy.',
            'Targeting coverage describes assignments, not distinct rule occurrences.',
            'No explicit target in XML is not proof of deployment.',
            'Device-only assignments do not establish a specific VSYS.',
            'Local policies, overrides, push status, template stacks and runtime state are not merged.',
            'Assignment aliases are report-local; no customer device, VSYS or rule names are exported.'
        ]
    }


def privacy_safe_panorama_diagnostics(diagnostics):
    """Export stable-in-report aliases without exposing internal object names.

    Do not infer relationships when source names are ambiguous or redacted.
    """
    from collections import Counter as _Counter
    import re

    groups = diagnostics.get("device_groups", [])
    templates = diagnostics.get("templates", [])
    stacks = diagnostics.get("template_stacks", [])
    scopes = diagnostics.get("policy_scopes", [])

    def mapping(values, prefix):
        return {name: f"{prefix}-{i:03d}" for i, name in enumerate(
            sorted({v for v in values if isinstance(v, str) and v}), 1)}

    gm = mapping([g.get("name") for g in groups], "DG")
    tm = mapping(templates + [t for st in stacks for t in st.get("templates", [])], "TPL")
    sm = mapping([st.get("name") for st in stacks], "STACK")
    name_counts = _Counter(g.get("name") for g in groups)
    stack_counts = _Counter(st.get("name") for st in stacks)

    # Scope is an internal representation, not an effective-policy locator.
    # Replace each path component, preserving repeated identifiers consistently.
    other_scopes = mapping([part for sc in scopes for part in sc.get("scope", "").split(" > ")
                            if not part.startswith("device-group:")], "SCOPE")
    def safe_scope(scope):
        result = []
        for part in scope.split(" > "):
            if part.startswith("device-group:"):
                raw = part[len("device-group:"):]
                result.append("device-group:" + gm.get(raw, "UNRESOLVED-DG"))
            else:
                result.append(other_scopes.get(part, "UNRESOLVED-SCOPE"))
        return " > ".join(result)

    safe = {k: v for k, v in diagnostics.items() if k not in (
        "policy_scopes", "device_groups", "templates", "template_stacks",
        "missing_parent_device_groups")}
    safe["privacy"] = {
        "mode": "consistent per-report aliases; mapping is not exported",
        "warning": "If input names were already replaced with the same redaction string, original identities and relationships cannot be recovered",
        "duplicate_device_group_names": sum(n-1 for n in name_counts.values() if n > 1),
        "duplicate_template_stack_names": sum(n-1 for n in stack_counts.values() if n > 1),
        "unmatched_policy_scope_groups": sum(
            1 for sc in scopes if any(part.startswith("device-group:") and
                part[len("device-group:"):] not in gm for part in sc.get("scope", "").split(" > "))),
    }
    safe["device_groups"] = [{"id": gm.get(g.get("name"), "UNRESOLVED-DG"),
        "parent_id": gm.get(g.get("parent"), "UNRESOLVED-DG") if g.get("parent") else None,
        "devices": g.get("devices", 0)} for g in groups]
    safe["missing_parent_device_groups"] = [gm.get(n, "UNRESOLVED-DG") for n in
                                              diagnostics.get("missing_parent_device_groups", [])]
    safe["templates"] = [tm.get(t, "UNRESOLVED-TPL") for t in templates]
    safe["template_stacks"] = [{"id": sm.get(st.get("name"), "UNRESOLVED-STACK"),
        "templates": [tm.get(t, "UNRESOLVED-TPL") for t in st.get("templates", [])],
        "devices": st.get("devices", 0)} for st in stacks]
    safe["policy_scopes"] = [{**sc, "scope": safe_scope(sc.get("scope", ""))} for sc in scopes]
    safe["identity_quality"] = {
        "device_group_records": len(groups),
        "unique_device_group_names": len(gm),
        "template_stack_records": len(stacks),
        "unique_template_stack_names": len(sm),
        "device_group_parent_links": sum(bool(g.get("parent")) for g in groups),
        "warning": "Name collisions prevent reliable inheritance resolution" if
                   any(n > 1 for n in name_counts.values()) or any(n > 1 for n in stack_counts.values()) else None,
    }
    return safe



def audit_policy_references(scanner):
    """Portable, read-only audit for PAN-OS firewall and Panorama XML.

    Each reference visit has exactly one primary outcome. Nested references
    are attributed to the originating policy type, avoiding v3.0.6's
    top-level-only accounting discrepancy.
    """
    import ipaddress
    from collections import Counter, defaultdict

    root = scanner.root
    index = defaultdict(lambda: defaultdict(dict))
    kinds = ("address", "address-group", "service", "service-group")
    containers = [("shared", root.find("./shared"))]
    for path in ("./devices/entry/device-group/entry", "./device-group/entry",
                 "./devices/entry/vsys/entry", "./vsys/entry"):
        containers.extend((scanner.scope(node), node) for node in root.findall(path))
    duplicate_definitions = 0
    for scope, container in containers:
        if container is None:
            continue
        for kind in kinds:
            for node in container.findall(f"./{kind}/entry"):
                name = node.get("name")
                if not name:
                    continue
                if name in index[scope][kind]:
                    duplicate_definitions += 1
                index[scope][kind][name] = node

    totals = Counter()
    by_type = defaultdict(Counter)
    by_family = defaultdict(Counter)
    by_depth = Counter()
    unresolved_unique = set()
    outcomes = ("builtin", "literal", "resolved_local", "resolved_shared",
                "unresolved", "ambiguous", "cycle", "dynamic_group", "unsupported_group")

    def visit(name, scope, family, policy_type, stack=frozenset(), depth=0):
        counter = by_type[policy_type]
        family_counter = by_family[family]
        totals["reference_visits"] += 1
        counter["reference_visits"] += 1
        family_counter["reference_visits"] += 1
        by_depth[str(min(depth, 20))] += 1

        def mark(outcome):
            totals[outcome] += 1
            counter[outcome] += 1
            family_counter[outcome] += 1
            return outcome

        if not isinstance(name, str) or not name.strip():
            unresolved_unique.add((scope, family, str(name)))
            return mark("unresolved")
        name = name.strip()
        if name.lower() in ("any", "application-default"):
            return mark("builtin")
        if family == "address":
            try:
                ipaddress.ip_network(name, strict=False)
                return mark("literal")
            except ValueError:
                pass
        object_types = (("address", "address-group") if family == "address"
                        else ("service", "service-group"))
        for candidate in ([scope] if scope == "shared" else [scope, "shared"]):
            hits = [(kind, index[candidate][kind][name]) for kind in object_types
                    if name in index[candidate][kind]]
            if len(hits) > 1:
                return mark("ambiguous")
            if not hits:
                continue
            kind, node = hits[0]
            if kind.endswith("-group"):
                identity = (candidate, kind, name)
                if identity in stack:
                    return mark("cycle")
                if node.find("./dynamic") is not None:
                    return mark("dynamic_group")
                child_path = "./static" if family == "address" else "./members"
                children = members(node, child_path)
                if not children:
                    return mark("unsupported_group")
                # The group reference itself is resolved; nested failures are
                # separately counted and never hidden by the parent outcome.
                result = mark("resolved_local" if candidate == scope else "resolved_shared")
                for child in children:
                    visit(child, scope, family, policy_type,
                          stack | {identity}, depth + 1)
                return result
            return mark("resolved_local" if candidate == scope else "resolved_shared")
        unresolved_unique.add((scope, family, name))
        return mark("unresolved")

    for policy_type, rules in (("security", scanner.security_rules),
                               ("nat", scanner.nat_rules),
                               ("decryption", scanner.decryption_rules)):
        for rule in rules:
            totals["policies_audited"] += 1
            by_type[policy_type]["policies"] += 1
            for field, family in (("source", "address"),
                                  ("destination", "address"),
                                  ("service", "service")):
                for name in rule.get(field, []):
                    totals[f"top_level_{family}_references"] += 1
                    by_type[policy_type]["top_level_references"] += 1
                    visit(name, rule.get("scope", "device/local"), family, policy_type)

    totals["duplicate_object_definitions"] = duplicate_definitions
    totals["unique_unresolved_scope_family_name"] = len(unresolved_unique)
    accounted = sum(totals[o] for o in outcomes)
    totals["outcome_accounting_difference"] = totals["reference_visits"] - accounted
    totals["policy_type_visit_difference"] = (totals["reference_visits"] -
                                              sum(c["reference_visits"] for c in by_type.values()))
    return {
        "method": "generic offline XML reference audit; no effective-policy claim",
        "lookup_order": "exact scope then shared; never unrelated device groups",
        "counts": dict(sorted(totals.items())),
        "policy_types": {k: dict(sorted(v.items())) for k, v in sorted(by_type.items())},
        "reference_families": {k: dict(sorted(v.items())) for k, v in sorted(by_family.items())},
        "nesting_depth_visits": dict(sorted(by_depth.items(), key=lambda p: int(p[0]))),
        "accounting_valid": (totals["outcome_accounting_difference"] == 0 and
                             totals["policy_type_visit_difference"] == 0),
        "limitations": [
            "Reference visits are not unique objects or unique policy rules.",
            "Only source, destination and service fields are audited.",
            "Dynamic groups cannot be expanded without runtime context.",
            "No effective per-firewall policy, local override, or template-stack overlay.",
            "Unresolved references may reflect sanitized or incomplete XML.",
            "Unique unresolved identifiers are counted but never exported.",
        ],
    }




def normalized_configuration_diagnostics(scanner):
    """Privacy-safe, generic configuration-model inventory (not effective policy).

    Normalizes scope identity and rule provenance without exporting original
    names, addresses, hostnames, or rule identifiers. This is intentionally
    independent from the existing detection engine.
    """
    from collections import Counter, defaultdict

    root = scanner.root
    scope_ids = {}
    scope_types = {}
    scope_counters = Counter()
    object_counts = Counter()
    policy_counts = Counter()
    rule_layers = Counter()
    rule_layers_by_type = defaultdict(Counter)
    rule_layers_by_scope = defaultdict(Counter)
    missing_scopes = Counter()
    policy_samples = []

    def normalize_scope(raw):
        raw = str(raw or 'device/local')
        segments = [x.strip() for x in raw.split(' > ') if x.strip()]
        # Specific scope type takes precedence over the enclosing device.
        typ = 'local'
        for prefix, target in (('device-group:', 'device_group'),
                               ('vsys:', 'vsys'),
                               ('template-stack:', 'template_stack'),
                               ('template:', 'template')):
            if any(seg.startswith(prefix) for seg in segments):
                typ = target
                break
        else:
            if 'shared' in segments:
                typ = 'shared'
            elif any(seg.startswith('device:') for seg in segments):
                typ = 'device'
        if raw not in scope_ids:
            scope_counters[typ] += 1
            scope_ids[raw] = f'{typ.upper()}-{scope_counters[typ]:04d}'
            scope_types[raw] = typ
        return scope_ids[raw], typ

    # Index only explicit object definitions in supported local/shared scopes.
    containers = [('shared', root.find('./shared'))]
    for path in ('./devices/entry/device-group/entry', './device-group/entry',
                 './devices/entry/vsys/entry', './vsys/entry'):
        containers.extend((scanner.scope(e), e) for e in root.findall(path))
    for raw_scope, container in containers:
        if container is None:
            continue
        sid, typ = normalize_scope(raw_scope)
        for kind in ('address', 'address-group', 'service', 'service-group'):
            n = len(container.findall(f'./{kind}/entry'))
            object_counts[kind] += n
            if n:
                object_counts[f'{typ}:{kind}'] += n

    # Build a provenance inventory, not a second copy of the policy engine.
    for kind, rules in (('security', scanner.security_rules),
                        ('nat', scanner.nat_rules),
                        ('decryption', scanner.decryption_rules)):
        for rule in rules:
            raw_scope = rule.get('scope', 'device/local')
            sid, typ = normalize_scope(raw_scope)
            policy_counts[kind] += 1
            policy_counts[f'{typ}:{kind}'] += 1
            # Rule dictionaries vary across PAN-OS versions and adapters.
            # Missing layer is explicitly recorded rather than guessed.
            layer = str(rule.get('layer') or rule.get('rulebase') or 'unknown')
            if layer not in ('pre-rulebase', 'post-rulebase', 'rulebase'):
                layer = 'unknown'
            rule_layers[layer] += 1
            rule_layers_by_type[kind][layer] += 1
            rule_layers_by_scope[sid][layer] += 1
            if len(policy_samples) < 8:
                policy_samples.append({'type': kind, 'scope_id': sid, 'scope_type': typ,
                                       'layer': layer})

    # Detect policy scopes that are not backed by an explicit object container.
    container_scope_set = {raw for raw, node in containers if node is not None}
    for kind, rules in (('security', scanner.security_rules),
                        ('nat', scanner.nat_rules),
                        ('decryption', scanner.decryption_rules)):
        for rule in rules:
            raw_scope = str(rule.get('scope', 'device/local'))
            if raw_scope not in container_scope_set:
                missing_scopes[kind] += 1

    return {
        'schema_version': '1.0',
        'model': 'normalized diagnostic inventory; not effective policy',
        'source_type': ('panorama' if root.findall('.//device-group/entry') or
                        root.findall('.//template-stack/entry') else 'standalone_or_other'),
        'scope_counts': dict(sorted(Counter(scope_types.values()).items())),
        'object_counts': dict(sorted(object_counts.items())),
        'policy_counts': dict(sorted(policy_counts.items())),
        'rule_layers': dict(sorted(rule_layers.items())),
        'rule_layers_by_type': {k: dict(sorted(v.items())) for k, v in sorted(rule_layers_by_type.items())},
        'rule_layers_by_scope': {k: dict(sorted(v.items())) for k, v in sorted(rule_layers_by_scope.items())},
        'layer_accounting_valid': (sum(rule_layers.values()) == sum(policy_counts[k] for k in ('security', 'nat', 'decryption')) and all(sum(v.values()) == policy_counts[k] for k, v in rule_layers_by_type.items())),
        'policy_scopes_without_object_container': dict(sorted(missing_scopes.items())),
        'policy_samples': policy_samples,
        'privacy': 'generated scope IDs only; original identifiers omitted',
        'limitations': [
            'Scope identifiers are diagnostic and are not stable across different input exports.',
            'Unknown policy layer is reported when XML lacks a recognized rulebase ancestor.',
            'Object inventory does not expand nested groups or compute effective policy.',
            'A policy scope without an object container is not necessarily invalid.',
            'No inheritance, template overlays, or runtime evaluation is claimed.'
        ],
    }

def scan_one(xml_path, out, baseline, privacy, formats=None, combined_writer=None, group_findings=True, combined_evidence_writer=None):
    formats = set(formats or ("html", "pdf", "csv", "json"))
    scanner = Scanner(xml_path, baseline)
    scanner.run()
    configuration_coverage = standalone_coverage_inventory(scanner)
    status, coverage_note = detect_coverage(scanner, configuration_coverage)
    data = scanner.output_data()
    raw_findings = data["findings"]
    data["metadata"]["detected_finding_count"] = len(raw_findings)
    data["metadata"]["findings_grouped"] = bool(group_findings)
    if group_findings:
        data["findings"] = consolidate_findings(raw_findings)
    diagnostics = panorama_diagnostics(scanner)
    data["metadata"]["scan_status"] = status
    data["metadata"]["coverage_note"] = coverage_note
    data = apply_privacy(data, privacy, secrets.token_hex(16))
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    outputs = {
        "json": out / "H4wkEye-report.json",
        "csv": out / "H4wkEye-report.csv",
        "evidence_csv": out / "H4wkEye-evidence.csv",
        "html": out / "H4wkEye-report.html",
        "pdf": out / "H4wkEye-report.pdf",
    }
    # A separate diagnostic artifact avoids silently treating raw inventory as resolved policy.
    diagnostic_path = out / "H4wkEye-coverage.json"
    # Always pseudonymize the coverage diagnostic, including in standard mode.
    # Strict mode still omits detailed topology.
    diagnostic_export = privacy_safe_panorama_diagnostics(diagnostics)
    diagnostic_export["reference_audit"] = audit_policy_references(scanner)
    diagnostic_export["normalized_model"] = normalized_configuration_diagnostics(scanner)
    diagnostic_export["configuration_coverage"] = configuration_coverage
    diagnostic_export["panorama_inheritance_preview"] = panorama_inheritance_preview(scanner) if diagnostics.get("device_groups") else None
    diagnostic_export["panorama_targeting_preview"] = panorama_targeting_preview(scanner) if diagnostics.get("device_groups") else None
    diagnostic_export["panorama_membership_preview"] = panorama_membership_preview(scanner) if diagnostics.get("device_groups") else None
    diagnostic_export["panorama_candidate_mapping_preview"] = panorama_candidate_mapping_preview(scanner) if diagnostics.get("device_groups") else None
    diagnostic_export["panorama_applicability_preview"] = panorama_applicability_preview(scanner) if diagnostics.get("device_groups") else None
    diagnostic_export["panorama_reconciliation_preview"] = panorama_reconciliation_preview(
        diagnostic_export["panorama_candidate_mapping_preview"],
        diagnostic_export["panorama_applicability_preview"],
        diagnostic_export.get("raw_policy_entries")) if diagnostics.get("device_groups") else None
    diagnostic_export["address_resolution"] = {
        "strategy": "exact-policy-scope-then-shared; no unrelated device-group fallback",
        "counts": dict(scanner.resolution_statistics),
        "note": "Counts are lookup events during existing finding evaluations, not a full-policy reference audit.",
    }
    if privacy == "strict":
        diagnostic_export = {k: v for k, v in diagnostic_export.items()
                             if k not in ("policy_scopes", "device_groups", "templates", "template_stacks")}
    write_json(diagnostic_path, diagnostic_export)
    chmod_private(diagnostic_path)
    if combined_writer is not None:
        config_label = (xml_path.name if privacy == "standard" else
                        hashlib.sha256(xml_path.name.encode()).hexdigest()[:12])
        for finding in data["findings"]:
            summary_row = dict(finding)
            summary_row["original_finding_ids"] = ";".join(finding.get("original_finding_ids", []))
            combined_writer.writerow({**summary_row, "configuration": config_label, "scan_status": status})
    if combined_evidence_writer is not None:
        config_label = (xml_path.name if privacy == "standard" else
                        hashlib.sha256(xml_path.name.encode()).hexdigest()[:12])
        for row in evidence_rows(data["findings"]):
            combined_evidence_writer.writerow({**row, "configuration": config_label, "scan_status": status})
    if "json" in formats:
        write_json(outputs["json"], data)
    if "csv" in formats:
        write_csv(outputs["csv"], data["findings"])
        write_evidence_csv(outputs["evidence_csv"], data["findings"])
    if "html" in formats:
        write_html(outputs["html"], data)
    pdf_error = None
    if "pdf" in formats:
        try:
            write_pdf(outputs["pdf"], data)
        except Exception as exc:
            # PDF failures must not discard other reports or scan findings.
            pdf_error = f"{type(exc).__name__}: {str(exc)[:400]}"
            outputs["pdf"].unlink(missing_ok=True)
            print(f"[!] PDF report unavailable for {xml_path.name}: {pdf_error}", file=sys.stderr)
    for path in outputs.values():
        if path.exists():
            chmod_private(path)
    return {
        "configuration": xml_path.name if privacy == "standard" else
                         hashlib.sha256(xml_path.name.encode()).hexdigest()[:12],
        "status": status,
        "coverage_note": coverage_note,
        "configuration_coverage": {
            "local_policy_status": configuration_coverage.get("local_policy_status", "NOT_APPLICABLE"),
            "effective_policy_status": configuration_coverage.get("effective_policy_status", "NOT_DETERMINED"),
            "structure_warning_count": sum(configuration_coverage.get("structure_warnings", {}).values()),
        },
        "pdf_status": ("NOT_REQUESTED" if "pdf" not in formats else
                       "FAILED" if pdf_error else "GENERATED"),
        "requested_formats": sorted(formats),
        "generated_formats": sorted(k for k, p in outputs.items() if p.exists()),
        "coverage_diagnostics": "H4wkEye-coverage.json",
        "policy_count_mismatch": diagnostics["policy_count_mismatch"],
        "pdf_error": pdf_error,
        "findings": len(data["findings"]),
        "detected_findings": len(raw_findings),
        "severity": dict(Counter(f["severity"] for f in data["findings"])),
        "output_folder": out.name if privacy == "standard" else "pseudonymized",
    }


def main():
    parser = argparse.ArgumentParser(
        description="H4wkEye - offline PAN-OS XML configuration scanner")
    parser.add_argument("xml", nargs="?", help="Single PAN-OS XML configuration")
    parser.add_argument("--input-dir", help="Folder containing XML configurations")
    parser.add_argument("--output", "--output-dir", dest="output", default=None)
    parser.add_argument("--baseline", help="Optional JSON baseline override")
    parser.add_argument("--privacy", choices=("standard", "strict"), default="standard")
    parser.add_argument("--max-xml-mib", type=int, default=100,
                        help="Maximum XML input size in MiB (default: 100; maximum: 2048)")
    parser.add_argument("--format", "--formats", dest="formats", default="all",
                        help="Report format(s): all (default), pdf, html, csv, json; comma-separated allowed, e.g. pdf,csv")
    parser.add_argument("--no-group-findings", action="store_true",
                        help="Keep one report finding per original detection (disable default consolidation)")
    parser.add_argument("--combined-csv", action="store_true",
                        help="Batch mode: also generate one combined-findings.csv with findings from all successfully scanned XML files; independent of --format")
    parser.add_argument("--recursive", action="store_true",
                        help="Include XML files in subdirectories (batch mode)")
    args = parser.parse_args()
    supported = {"pdf", "html", "csv", "json"}
    selected = [item.strip().lower() for item in args.formats.split(",")]
    if not selected or any(not item for item in selected):
        parser.error("--format requires one or more formats: pdf,html,csv,json,all")
    if "all" in selected:
        if len(selected) != 1:
            parser.error("'all' cannot be combined with individual formats")
        selected_formats = supported
    else:
        invalid = set(selected) - supported
        if invalid:
            parser.error("Unsupported report format(s): " + ", ".join(sorted(invalid)))
        selected_formats = set(selected)
    if not 1 <= args.max_xml_mib <= 2048:
        parser.error("--max-xml-mib must be between 1 and 2048")
    global MAX_XML_BYTES
    MAX_XML_BYTES = args.max_xml_mib * 1024 * 1024
    if bool(args.xml) == bool(args.input_dir):
        parser.error("Provide either a single XML file or --input-dir")
    if args.combined_csv and not args.input_dir:
        parser.error("--combined-csv requires --input-dir (batch mode)")
    try:
        baseline = load_baseline(args.baseline)
    except (OSError, ValueError) as exc:
        print(f"[!] Baseline error: {exc}", file=sys.stderr)
        return 2

    if args.xml:
        path = Path(args.xml)
        if not path.is_file():
            print(f"[!] Configuration not found: {path}", file=sys.stderr)
            return 2
        out = Path(args.output or ".")
        try:
            result = scan_one(path, out, baseline, args.privacy, selected_formats,
                              group_findings=not args.no_group_findings)
        except Exception as exc:
            print(f"[!] Scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 4
        print(f"H4wkEye v{VERSION} | {result['status']} | "
              f"findings={result['findings']} | {result['coverage_note']}")
        print(f"Reports: {out.resolve()}")
        return 0

    folder = Path(args.input_dir)
    if not folder.is_dir():
        print(f"[!] Input folder not found: {folder}", file=sys.stderr)
        return 2
    files = sorted(folder.rglob("*.xml") if args.recursive else folder.glob("*.xml"))
    files = [p for p in files if p.is_file() and not p.is_symlink()]
    if not files:
        print("[!] No XML files found", file=sys.stderr)
        return 2

    base = Path(args.output or "./reports")
    batch = base / datetime.now().strftime("%Y-%m-%d_%H%M%S")
    if batch.exists():
        batch = base / (batch.name + "_" + secrets.token_hex(3))
    batch.mkdir(parents=True, mode=0o700)
    results = []
    combined_file = None
    combined_writer = None
    evidence_file = None
    combined_evidence_writer = None
    combined_path = batch / "combined-findings.csv"
    combined_evidence_path = batch / "combined-evidence.csv"
    if args.combined_csv:
        combined_file = open(combined_path, "w", newline="", encoding="utf-8-sig")
        combined_writer = csv.DictWriter(
            combined_file, fieldnames=["configuration", "scan_status", *csv_fields()],
            extrasaction="ignore")
        combined_writer.writeheader()
        evidence_file = open(combined_evidence_path, "w", newline="", encoding="utf-8-sig")
        evidence_fields = ["configuration", "scan_status", "finding_id", "title", "severity",
                          "section", "affected_count", "original_finding_id", *REPORT_EVIDENCE_FIELDS]
        combined_evidence_writer = csv.DictWriter(evidence_file, fieldnames=evidence_fields,
                                                 extrasaction="ignore")
        combined_evidence_writer.writeheader()
    for index, path in enumerate(files, 1):
        # Numbered names avoid collisions; strict mode never writes source names.
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", path.stem)[:70].strip("._") or "config"
        dirname = f"{index:03d}_{safe_name}" if args.privacy == "standard" else f"{index:03d}_config"
        out = batch / dirname
        try:
            result = scan_one(path, out, baseline, args.privacy, selected_formats,
                              combined_writer, group_findings=not args.no_group_findings,
                              combined_evidence_writer=combined_evidence_writer)
        except Exception as exc:
            # Surface the real error without exposing XML content or credentials.
            error_detail = (str(exc) if str(exc).startswith("EMPTY_FILE:")
                            else f"{type(exc).__name__}: {exc}")
            print(f"[!] {path.name if args.privacy == 'standard' else f'config-{index:03d}'}: {error_detail}", file=sys.stderr)
            result = {
                "configuration": path.name if args.privacy == "standard" else f"config-{index:03d}",
                "status": "FAILED", "coverage_note": error_detail,
                "error_code": "EMPTY_FILE" if error_detail.startswith("EMPTY_FILE:") else type(exc).__name__,
                "findings": 0, "severity": {}, "output_folder": dirname}
        results.append(result)
        print(f"[{index}/{len(files)}] {result['configuration']}: "
              f"{result['status']} ({result['findings']} findings)")

    if combined_file is not None:
        combined_file.close()
        chmod_private(combined_path)
    if evidence_file is not None:
        evidence_file.close()
        chmod_private(combined_evidence_path)
    summary = {"scanner": "H4wkEye", "version": VERSION,
               "generated": datetime.now().isoformat(timespec="seconds"),
               "privacy_mode": args.privacy, "files": results,
               "combined_csv": "combined-findings.csv" if args.combined_csv else None,
               "combined_evidence_csv": "combined-evidence.csv" if args.combined_csv else None,
               "status_counts": dict(Counter(r["status"] for r in results))}
    summary_path = batch / "batch-summary.json"
    write_json(summary_path, summary)
    chmod_private(summary_path)
    print(f"Batch reports: {batch.resolve()}")
    return 1 if any(r["status"] == "FAILED" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())