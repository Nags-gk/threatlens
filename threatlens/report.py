"""Outputs: Mermaid data-flow diagram, Markdown review, JSON, and SARIF 2.1.0 so findings
show up in GitHub code scanning on the pull request that changes the design."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict

from .engine import Finding
from .model import PLAINTEXT, Spec

RATING_ORDER = ["critical", "high", "medium", "low"]
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _mid(s: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in s)


def dfd(spec: Spec, findings: list[Finding] | None = None) -> str:
    """Mermaid flowchart: one subgraph per trust zone (ordered by trust), components
    flagged red when they carry open high/critical findings, plaintext or
    unauthenticated hops drawn dashed."""
    hot = {f.element for f in findings or [] if f.status == "open" and f.rating in ("critical", "high")}
    shapes = {"datastore": ("[(", ")]"), "log_sink": ("[(", ")]"), "queue": ("[(", ")]"), "client": ("([", "])"),
              "device": ("[/", "/]"), "third_party": ("{{", "}}")}
    lines = ["flowchart LR"]
    for zone, trust in sorted(spec.zones.items(), key=lambda kv: kv[1]):
        members = [c for c in spec.components.values() if c.zone == zone]
        if not members:
            continue
        lines.append(f'  subgraph z_{_mid(zone)}["{zone} (trust {trust})"]')
        for c in members:
            a, b = shapes.get(c.type, ("[", "]"))
            lines.append(f'    {_mid(c.id)}{a}"{c.id}<br/><small>{c.type}</small>"{b}')
        lines.append("  end")
    for f in spec.flows:
        weak = f.protocol in PLAINTEXT or f.auth == "none"
        arrow = "-.->" if weak else "-->"
        label = f"{f.protocol} / {f.auth}"
        lines.append(f'  {_mid(f.source)} {arrow}|"{label}"| {_mid(f.target)}')
    for el in sorted(hot & set(spec.components)):
        lines.append(f"  style {_mid(el)} stroke:#d93025,stroke-width:3px")
    return "\n".join(lines)


def summary(findings: list[Finding]) -> dict:
    open_ = [f for f in findings if f.status == "open"]
    return dict(open=len(open_), accepted=len(findings) - len(open_),
                by_rating={r: sum(1 for f in open_ if f.rating == r) for r in RATING_ORDER},
                by_category=dict(Counter(f.category for f in open_)),
                by_stride=dict(Counter(f.stride for f in open_)))


def to_json(spec: Spec, findings: list[Finding]) -> str:
    return json.dumps(dict(system=spec.name, summary=summary(findings), findings=[asdict(f) for f in findings],
                           dfd=dfd(spec, findings)), indent=2)


def to_markdown(spec: Spec, findings: list[Finding]) -> str:
    s = summary(findings)
    out = [f"# Security design review: {spec.name}", "", spec.description, "",
           f"**Open findings:** {s['open']} ({', '.join(f'{v} {k}' for k, v in s['by_rating'].items() if v)}) · "
           f"**Accepted risks:** {s['accepted']}", "",
           "## Data-flow diagram", "", "Dashed edges are plaintext or unauthenticated hops; red components carry open high or critical findings.",
           "", "```mermaid", dfd(spec, findings), "```", "",
           "## Findings", "", "| Risk | Rating | ID | Element | STRIDE | Lens | Finding |", "|---:|---|---|---|---|---|---|"]
    for f in findings:
        if f.status == "open":
            out.append(f"| {f.risk} | {f.rating} | {f.rule} | `{f.element}` | {f.stride} | {f.category} | {f.title} |")
    for lens in ("access", "abuse", "logging", "data"):
        items = [f for f in findings if f.status == "open" and f.category == lens]
        if not items:
            continue
        out += ["", f"## Recommended changes: {lens}", ""]
        for f in items:
            refs = " · ".join(x for x in (f.cwe, f.capec, f.attack) if x)
            out.append(f"- **{f.rule} on `{f.element}` ({f.rating}).** {f.threat} **Change:** {f.recommendation}" + (f" _({refs})_" if refs else ""))
    acc = [f for f in findings if f.status == "accepted"]
    if acc:
        out += ["", "## Accepted risks", ""] + [f"- {f.rule} on `{f.element}`: {f.title}. Justification: {f.accepted_reason}" for f in acc]
    return "\n".join(out) + "\n"


def to_sarif(spec: Spec, findings: list[Finding], spec_path: str = "architecture.yml") -> str:
    rules, seen = [], set()
    for f in findings:
        if f.rule not in seen:
            seen.add(f.rule)
            rules.append({"id": f.rule, "name": f.title, "shortDescription": {"text": f.title},
                          "fullDescription": {"text": f.threat}, "help": {"text": f.recommendation},
                          "properties": {"tags": [f.stride, f.category] + [x for x in (f.cwe, f.capec, f.attack) if x],
                                         "security-severity": str(min(10.0, f.risk / 2.5))}})
    results = [{"ruleId": f.rule, "level": SARIF_LEVEL[f.rating],
                "message": {"text": f"{f.title} on '{f.element}'. {f.recommendation}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": spec_path}, "region": {"startLine": 1}},
                               "logicalLocations": [{"name": f.element, "kind": f.element_kind}]}],
                "partialFingerprints": {"element/rule": f"{f.element}/{f.rule}"}}
               for f in findings if f.status == "open"]
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "ThreatLens", "informationUri": "https://github.com/Nags-gk/threatlens",
                                                     "rules": rules}}, "results": results}]}, indent=2)
