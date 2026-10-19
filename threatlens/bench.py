"""Seeded-flaw benchmark.

Start from hardened reference architectures that produce no findings, then apply
one design flaw at a time (drop TLS on a flow, remove MFA, share a device key...).
Each mutation records the finding a reviewer should raise and the element it should
be raised on. A reviewer (the rule engine, an LLM, or both) is scored on:

* detection rate: the expected finding appears on the expected element;
* localization: the finding points at the mutated element, not elsewhere;
* noise: findings on the unmutated baselines (should be none).

The mutation operators are written from the threat descriptions, not from the
rules, but the same author wrote both, so the rule-engine score mostly shows the
knowledge base covers what it claims. The LLM score is the more informative number.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from . import engine, model

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@dataclass
class Mutation:
    op: str
    description: str
    expected_rule: str
    element: str
    spec: dict


def _components(raw, pred):
    return [c for c in raw["components"] if pred(c)]


def _drop(lst, item):
    return [x for x in lst if x != item]


def _remove_control(control: str, rule: str, desc: str, pred: Callable) -> Callable:
    def op(raw):
        for c in _components(raw, lambda c: control in c.get("controls", []) and pred(c)):
            m = copy.deepcopy(raw)
            t = next(x for x in m["components"] if x["id"] == c["id"])
            t["controls"] = _drop(t["controls"], control)
            # strip alternative controls that would satisfy the same rule
            for alt in ALTERNATIVES.get(control, []):
                t["controls"] = _drop(t["controls"], alt)
            yield Mutation(f"remove_{control}", desc.format(id=c["id"]), rule, c["id"], m)
    return op


ALTERNATIVES = {"captcha": ["phone_verification", "bot_detection"], "breached_password_check": ["bot_detection"],
                "reauth": ["step_up"], "hardware_keys": ["attestation"], "context_aware_access": ["ip_allowlist"],
                "rate_limit": ["cooldown"]}


def _flow_op(field: str, value: str, rule: str, desc: str, pred: Callable) -> Callable:
    def op(raw):
        zones = raw["zones"]
        comps = {c["id"]: c for c in raw["components"]}
        for f in raw["flows"]:
            crosses = zones[comps[f["from"]]["zone"]] != zones[comps[f["to"]]["zone"]]
            if not pred(f, crosses, comps):
                continue
            m = copy.deepcopy(raw)
            next(x for x in m["flows"] if x["id"] == f["id"])[field] = value
            yield Mutation(f"set_{field}_{value}", desc.format(id=f["id"]), rule, f["id"], m)
    return op


def _comp_field(field: str, value, rule: str, desc: str, pred: Callable) -> Callable:
    def op(raw):
        for c in _components(raw, pred):
            m = copy.deepcopy(raw)
            next(x for x in m["components"] if x["id"] == c["id"])[field] = value
            yield Mutation(f"set_{field}", desc.format(id=c["id"]), rule, c["id"], m)
    return op


def _drop_detection(raw):
    if any(c["type"] == "detection" for c in raw["components"]):
        m = copy.deepcopy(raw)
        ids = {c["id"] for c in m["components"] if c["type"] == "detection"}
        m["components"] = [c for c in m["components"] if c["id"] not in ids]
        m["flows"] = [f for f in m["flows"] if f["from"] not in ids and f["to"] not in ids]
        yield Mutation("remove_detection", "Security logs are collected but no detection consumes them", "TL-L02", "system", m)


def _handles(*fns):
    return lambda c: bool(set(c.get("handles", [])) & set(fns))


OPERATORS = [
    _flow_op("protocol", "http", "TL-T01", "{id} downgraded to plaintext HTTP across a trust boundary",
             lambda f, x, c: x and f["protocol"] in ("https", "grpc_tls", "mqtts", "sql_tls", "internal_tls", "tls", "ble_secure")),
    _flow_op("auth", "none", "TL-S01", "{id} no longer authenticates its caller", lambda f, x, c: x and f["auth"] != "none"),
    _remove_control("mfa", "TL-S02", "{id} drops multi-factor authentication", lambda c: "login" in c.get("handles", []) and c.get("internet_facing")),
    _comp_field("device_auth", "shared_secret", "TL-S03", "{id} ships with one fleet-wide secret", lambda c: c["type"] == "device"),
    _remove_control("hardware_keys", "TL-S04", "{id} keeps its key in ordinary flash", lambda c: c["type"] == "device"),
    _remove_control("code_signing", "TL-T02", "{id} installs unsigned firmware", _handles("firmware_update")),
    _remove_control("rollback_protection", "TL-T03", "{id} accepts older firmware images", _handles("firmware_update")),
    _remove_control("input_validation", "TL-T04", "{id} stops validating request schemas", lambda c: c.get("internet_facing")),
    _remove_control("audit_logging", "TL-R01", "{id} stops writing audit records", _handles("login", "admin", "account_recovery", "number_port", "device_pairing", "policy_push", "data_export")),
    _remove_control("security_logging", "TL-L01", "{id} logs auth attempts without IP/ASN/device fields", _handles("login", "signup", "sms_otp", "device_checkin")),
    _drop_detection,
    _comp_field("log_retention_days", 14, "TL-L03", "{id} keeps logs for 14 days", lambda c: c["type"] == "log_sink"),
    _remove_control("log_integrity", "TL-L04", "{id} lets producers delete logs", lambda c: c["type"] == "log_sink"),
    _remove_control("encryption_at_rest", "TL-I01", "{id} stores data unencrypted", lambda c: c["type"] in ("datastore", "log_sink", "queue")),
    _remove_control("opaque_ids", "TL-I02", "{id} switches to sequential IDs", _handles("object_api")),
    _remove_control("authz", "TL-E04", "{id} skips the object ownership check", _handles("object_api", "data_export", "sync")),
    _remove_control("secret_manager", "TL-I04", "{id} reads secrets from env files", lambda c: "secrets" in c.get("data", [])),
    _remove_control("generic_errors", "TL-I05", "{id} returns stack traces", lambda c: c.get("internet_facing") and c["type"] in ("service", "gateway")),
    _remove_control("rate_limit", "TL-D01", "{id} has no rate limit", lambda c: c.get("internet_facing") and c["type"] in ("service", "gateway", "identity_provider")),
    _remove_control("per_device_rate_limit", "TL-D02", "{id} lets one device flood check-ins", _handles("device_checkin")),
    _remove_control("context_aware_access", "TL-E01", "{id} is open to the internet with password login", lambda c: c["type"] == "admin_console"),
    _comp_field("iam", "broad", "TL-E02", "{id} runs with a project-wide editor role", lambda c: c["type"] in ("service", "identity_provider")),
    _remove_control("non_root", "TL-E03", "{id} runs as root", lambda c: c["type"] in ("service", "gateway", "detection")),
    _remove_control("captcha", "TL-A01", "{id} lets scripts create accounts", _handles("signup", "promo")),
    _remove_control("breached_password_check", "TL-A02", "{id} has no stuffing defenses", lambda c: "login" in c.get("handles", []) and c.get("internet_facing")),
    _remove_control("reauth", "TL-A03", "{id} changes recovery email without re-authentication", _handles("account_recovery")),
    _remove_control("physical_proof", "TL-A04", "{id} pairs devices remotely", _handles("device_pairing")),
    _remove_control("rate_limit", "TL-A05", "{id} sends unlimited SMS codes", _handles("sms_otp")),
    _remove_control("step_up", "TL-A06", "{id} ports numbers without step-up", _handles("number_port")),
    _remove_control("notify_user", "TL-A07", "{id} makes silent security changes", _handles("account_recovery", "device_pairing", "number_port", "enrollment")),
    _remove_control("attestation", "TL-A08", "{id} enrolls unattested devices", _handles("enrollment")),
    _remove_control("anomaly_detection", "TL-A09", "{id} exports data without volume alerts", _handles("data_export")),
    _remove_control("key_rotation", "TL-A10", "{id} never rotates keys", lambda c: c["type"] in ("device", "identity_provider")),
]


def baselines() -> dict[str, dict]:
    return {p.stem: yaml.safe_load(p.read_text()) for p in sorted(EXAMPLES.glob("*.yml"))}


def mutations() -> list[tuple[str, Mutation]]:
    out = []
    for name, raw in baselines().items():
        for op in OPERATORS:
            for m in op(raw):
                out.append((name, m))
    return out


def score_rules() -> dict:
    noise = {n: len(engine.review(model.load(r))) for n, r in baselines().items()}
    rows = []
    for name, m in mutations():
        fs = engine.review(model.load(m.spec))
        hit = any(f.rule == m.expected_rule and f.element == m.element for f in fs)
        rule_anywhere = any(f.rule == m.expected_rule for f in fs)
        rows.append(dict(arch=name, op=m.op, rule=m.expected_rule, element=m.element, detected=hit,
                         rule_elsewhere=rule_anywhere and not hit, findings=len(fs)))
    det = sum(r["detected"] for r in rows)
    return dict(mutations=len(rows), detected=det, detection_rate=round(det / len(rows), 4),
                operators=len(OPERATORS), rules_exercised=len({r["rule"] for r in rows}),
                baseline_findings=noise, misses=[r for r in rows if not r["detected"]], rows=rows)
