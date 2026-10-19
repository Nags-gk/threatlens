"""Rule engine: matches the knowledge base (kb.yml) against a spec.

Rules are declarative, so the engine has no eval() and the knowledge base is
reviewable by people who do not read Python. Predicates:

  type_in, handles_any, data_any, internet_facing, lacks (none of the listed controls
  present), device_auth_in, iam_in, retention_below            -> components
  crosses_boundary, from_internet, protocol_in, auth_in, data_any -> flows
  missing_component_type, no_component_with_control              -> system
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .model import SENSITIVE, Component, Flow, Spec

KB_PATH = Path(__file__).resolve().parent / "kb.yml"
SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    title: str
    stride: str
    category: str
    element: str
    element_kind: str
    likelihood: int
    impact: int
    risk: int
    rating: str
    threat: str
    recommendation: str
    cwe: str = ""
    capec: str = ""
    attack: str = ""
    source: str = "rules"
    status: str = "open"
    accepted_reason: str = ""


def load_kb(path: Path = KB_PATH) -> list[dict]:
    kb = yaml.safe_load(path.read_text())
    ids = [r["id"] for r in kb]
    assert len(ids) == len(set(ids)), "duplicate KB ids"
    return kb


def _comp_match(c: Component, w: dict) -> bool:
    checks = {
        "type_in": lambda v: c.type in v,
        "handles_any": lambda v: bool(set(c.handles) & set(v)),
        "data_any": lambda v: bool(set(c.data) & set(v)),
        "internet_facing": lambda v: c.internet_facing == v,
        "lacks": lambda v: not (set(c.controls) & set(v)),
        "device_auth_in": lambda v: c.device_auth in v,
        "iam_in": lambda v: c.iam in v,
        "retention_below": lambda v: c.log_retention_days is not None and c.log_retention_days < v,
    }
    return all(checks[k](v) for k, v in w.items())


def _flow_match(f: Flow, spec: Spec, w: dict) -> bool:
    src, dst = spec.components[f.source], spec.components[f.target]
    checks = {
        "crosses_boundary": lambda v: f.crosses_boundary == v,
        "from_internet": lambda v: f.from_internet == v,
        "protocol_in": lambda v: f.protocol in v,
        "auth_in": lambda v: f.auth in v,
        "data_any": lambda v: bool(set(f.data) & set(v)),
        "target_type_in": lambda v: dst.type in v,
        "source_type_in": lambda v: src.type in v,
    }
    return all(checks[k](v) for k, v in w.items())


def _system_match(spec: Spec, w: dict) -> bool:
    comps = spec.components.values()
    checks = {
        "missing_component_type": lambda v: not any(c.type == v for c in comps),
        "no_component_with_control": lambda v: not any(v in c.controls for c in comps),
    }
    return all(checks[k](v) for k, v in w.items())


def _score(rule: dict, element, spec: Spec) -> tuple[int, int, int, str]:
    lik, imp = rule.get("likelihood", 3), rule.get("impact", 3)
    if isinstance(element, Component):
        exposed = element.internet_facing or spec.zones[element.zone] == 0
        sensitive = bool(set(element.data) & SENSITIVE)
    elif isinstance(element, Flow):
        exposed = element.from_internet
        sensitive = bool(set(element.data) & SENSITIVE)
    else:
        exposed = sensitive = False
    lik, imp = min(5, lik + exposed), min(5, imp + sensitive)
    risk = lik * imp
    rating = "critical" if risk >= 20 else "high" if risk >= 12 else "medium" if risk >= 6 else "low"
    return lik, imp, risk, rating


def review(spec: Spec, kb: list[dict] | None = None) -> list[Finding]:
    kb = kb or load_kb()
    out = []
    for r in kb:
        targets = []
        if r["applies_to"] == "component":
            targets = [c for c in spec.components.values() if _comp_match(c, r["when"])]
        elif r["applies_to"] == "flow":
            targets = [f for f in spec.flows if _flow_match(f, spec, r["when"])]
        elif r["applies_to"] == "system" and _system_match(spec, r["when"]):
            targets = [None]
        for t in targets:
            lik, imp, risk, rating = _score(r, t, spec)
            el = t.id if t is not None else "system"
            acc = spec.accepted.get((r["id"], el))
            out.append(Finding(rule=r["id"], title=r["title"], stride=r["stride"], category=r["category"], element=el,
                               element_kind=r["applies_to"], likelihood=lik, impact=imp, risk=risk, rating=rating,
                               threat=r["threat"].strip(), recommendation=r["recommendation"].strip(),
                               cwe=r.get("cwe", ""), capec=r.get("capec", ""), attack=r.get("attack", ""),
                               status="accepted" if acc else "open", accepted_reason=acc["reason"] if acc else ""))
    return sorted(out, key=lambda f: (-f.risk, f.rule, f.element))
