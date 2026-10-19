"""Architecture spec: what a design under review looks like, and validation of it.

A spec lists trust zones, components and data flows. Fields are deliberately the
questions a security design review asks: who is on the internet, what data each
piece holds, which controls exist, how each hop is protected and authenticated.
"""
from __future__ import annotations

from dataclasses import dataclass, field

COMPONENT_TYPES = {"client", "gateway", "service", "datastore", "device", "queue", "admin_console",
                   "third_party", "log_sink", "ota_server", "identity_provider", "detection"}
FUNCTIONS = {"login", "signup", "account_recovery", "device_pairing", "sms_otp", "number_port", "promo", "admin",
             "firmware_update", "device_checkin", "object_api", "data_export", "enrollment", "policy_push", "sync"}
DATA = {"pii", "credentials", "health", "location", "payment", "secrets", "telemetry", "video", "logs", "policy", "contacts"}
SENSITIVE = {"credentials", "health", "location", "payment", "secrets", "video"}
CONTROLS = {"mfa", "rate_limit", "waf", "captcha", "phone_verification", "breached_password_check", "bot_detection",
            "reauth", "physical_proof", "step_up", "audit_logging", "security_logging", "encryption_at_rest",
            "access_logging", "hardware_keys", "attestation", "code_signing", "generic_errors", "ip_allowlist",
            "context_aware_access", "authz", "input_validation", "alerting", "data_minimization", "secret_manager",
            "non_root", "least_privilege_iam", "per_device_rate_limit", "opaque_ids", "log_integrity", "anomaly_detection",
            "fraud_hold", "notify_user", "cooldown", "rollback_protection", "consent", "key_rotation"}
PROTOCOLS = {"https", "http", "mqtt", "mqtts", "grpc", "grpc_tls", "ble", "ble_secure", "tls", "tcp", "sms", "sql",
             "sql_tls", "internal_tls", "smtp", "smtps"}
PLAINTEXT = {"http", "mqtt", "grpc", "ble", "tcp", "sql", "smtp"}
AUTH = {"none", "oauth2", "mtls", "api_key", "session", "password", "device_cert", "shared_key", "workload_identity", "signed_token"}


class SpecError(ValueError):
    pass


@dataclass
class Component:
    id: str
    type: str
    zone: str
    name: str = ""
    internet_facing: bool = False
    handles: list = field(default_factory=list)
    data: list = field(default_factory=list)
    controls: list = field(default_factory=list)
    device_auth: str = ""
    iam: str = ""
    log_retention_days: int | None = None
    notes: str = ""
    kind: str = "component"


@dataclass
class Flow:
    id: str
    source: str
    target: str
    protocol: str
    auth: str
    data: list = field(default_factory=list)
    name: str = ""
    crosses_boundary: bool = False
    from_internet: bool = False
    kind: str = "flow"


@dataclass
class Spec:
    name: str
    zones: dict
    components: dict
    flows: list
    description: str = ""
    accepted: dict = field(default_factory=dict)


def _check(cond, msg):
    if not cond:
        raise SpecError(msg)


def load(raw: dict) -> Spec:
    _check(isinstance(raw, dict), "spec must be a mapping")
    for key in ("name", "zones", "components", "flows"):
        _check(key in raw, f"missing top-level key '{key}'")
    zones = raw["zones"]
    _check(isinstance(zones, dict) and zones, "zones must map zone name -> trust level (0 = untrusted)")
    for z, t in zones.items():
        _check(isinstance(t, int) and 0 <= t <= 10, f"zone {z}: trust must be an int 0-10")
    comps = {}
    for c in raw["components"]:
        _check("id" in c and "type" in c and "zone" in c, f"component needs id, type, zone: {c}")
        _check(c["id"] not in comps, f"duplicate component id {c['id']}")
        _check(c["type"] in COMPONENT_TYPES, f"{c['id']}: unknown type {c['type']!r}")
        _check(c["zone"] in zones, f"{c['id']}: unknown zone {c['zone']!r}")
        for k, allowed in (("handles", FUNCTIONS), ("data", DATA), ("controls", CONTROLS)):
            bad = set(c.get(k, [])) - allowed
            _check(not bad, f"{c['id']}: unknown {k} {sorted(bad)}")
        comps[c["id"]] = Component(**{k: v for k, v in c.items() if k in Component.__dataclass_fields__})
    flows = []
    seen = set()
    for f in raw["flows"]:
        for k in ("id", "from", "to", "protocol", "auth"):
            _check(k in f, f"flow needs {k}: {f}")
        _check(f["id"] not in seen and f["id"] not in comps, f"duplicate id {f['id']}")
        seen.add(f["id"])
        _check(f["from"] in comps and f["to"] in comps, f"{f['id']}: endpoints must be component ids")
        _check(f["protocol"] in PROTOCOLS, f"{f['id']}: unknown protocol {f['protocol']!r}")
        _check(f["auth"] in AUTH, f"{f['id']}: unknown auth {f['auth']!r}")
        bad = set(f.get("data", [])) - DATA
        _check(not bad, f"{f['id']}: unknown data {sorted(bad)}")
        a, b = comps[f["from"]], comps[f["to"]]
        flows.append(Flow(id=f["id"], source=f["from"], target=f["to"], protocol=f["protocol"], auth=f["auth"],
                          data=f.get("data", []), name=f.get("name", ""),
                          crosses_boundary=zones[a.zone] != zones[b.zone],
                          from_internet=zones[a.zone] == 0))
    accepted = {}
    ids = set(comps) | {f.id for f in flows} | {"system"}
    for a in raw.get("accepted_risks", []) or []:
        _check({"rule", "element", "reason"} <= a.keys(), f"accepted risk needs rule, element, reason: {a}")
        _check(a["element"] in ids, f"accepted risk names unknown element {a['element']!r}")
        accepted[(a["rule"], a["element"])] = a
    return Spec(raw["name"], zones, comps, flows, raw.get("description", ""), accepted)
