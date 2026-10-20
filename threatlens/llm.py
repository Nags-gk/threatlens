"""Gemini as a second reviewer.

`augment` asks the model for threats the rule engine did not raise, mostly abuse cases
that depend on business logic. Every answer goes through a guard: the element must
exist in the spec, STRIDE and lens values must be valid, the mapped catalog ID (if
any) must exist, and suggestions that duplicate a rule finding on the same element
are dropped. `bench_llm` measures the model alone on the seeded-flaw benchmark.
"""
from __future__ import annotations

import json
import os
import random
import re
import time
from dataclasses import asdict

from . import bench, engine, model
from .engine import Finding

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
STRIDE = {"Spoofing", "Tampering", "Repudiation", "Information disclosure", "Denial of service", "Elevation of privilege"}
LENSES = {"access", "abuse", "logging", "data"}

SCHEMA = {
    "type": "object",
    "properties": {"threats": {"type": "array", "items": {"type": "object", "properties": {
        "element": {"type": "string"}, "catalog_id": {"type": "string"}, "title": {"type": "string"},
        "stride": {"type": "string"}, "lens": {"type": "string"}, "likelihood": {"type": "integer"},
        "impact": {"type": "integer"}, "threat": {"type": "string"}, "recommendation": {"type": "string"}},
        "required": ["element", "catalog_id", "title", "stride", "lens", "likelihood", "impact", "threat", "recommendation"]}}},
    "required": ["threats"],
}


def _tokens(s: str) -> set:
    return {w for w in re.findall(r"[a-z]+", s.lower()) if len(w) > 3}


def _catalog(kb) -> str:
    return "\n".join(f"{r['id']}: {r['title']}" for r in kb)


def _prompt(raw: dict, kb, findings: list[Finding] | None, n: int) -> str:
    known = "" if findings is None else "Already raised by the rule engine (do not repeat):\n" + "\n".join(
        f"- {f.rule} on {f.element}: {f.title}" for f in findings) + "\n\n"
    return (f"You are a security engineer doing a design review for a consumer device platform. Review this architecture "
            f"spec and list the {n} most important security threats to access control, abuse of features, logging, or data.\n"
            f"Use element ids exactly as they appear in the spec (component or flow id, or 'system'). For each threat, set "
            f"catalog_id to the closest entry in this catalog, or 'NEW' if none fits:\n{_catalog(kb)}\n\n{known}"
            f"stride must be one of {sorted(STRIDE)}; lens one of {sorted(LENSES)}; likelihood and impact 1-5.\n\n"
            f"Spec:\n{json.dumps(raw)}")


def _call(prompt: str, api_key: str) -> list[dict]:
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=api_key)
    for attempt in range(4):
        try:
            resp = client.models.generate_content(
                model=MODEL, contents=prompt,
                config=types.GenerateContentConfig(temperature=0.2, response_mime_type="application/json", response_schema=SCHEMA))
            return json.loads(resp.text)["threats"]
        except Exception as e:  # rate limits on the free tier: back off and retry
            if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                time.sleep(20 * (attempt + 1))
                continue
            raise
    raise RuntimeError("Gemini rate limit: retries exhausted")


def guard(threats: list[dict], spec: model.Spec, kb, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
    ids = set(spec.components) | {f.id for f in spec.flows} | {"system"}
    kb_ids = {r["id"] for r in kb}
    accepted, rejected = [], []
    for t in threats:
        why = []
        if t["element"] not in ids:
            why.append(f"unknown element {t['element']!r}")
        if t["stride"] not in STRIDE:
            why.append(f"bad STRIDE {t['stride']!r}")
        if t["lens"] not in LENSES:
            why.append(f"bad lens {t['lens']!r}")
        if t["catalog_id"] != "NEW" and t["catalog_id"] not in kb_ids:
            why.append(f"unknown catalog id {t['catalog_id']!r}")
        dup = [f for f in findings if f.element == t["element"] and
               (f.rule == t["catalog_id"] or len(_tokens(f.title) & _tokens(t["title"])) / max(1, len(_tokens(t["title"]))) >= 0.5)]
        if dup:
            why.append(f"duplicates {dup[0].rule}")
        if why:
            rejected.append(f"{t.get('title', '?')}: {'; '.join(why)}")
            continue
        lik, imp = max(1, min(5, int(t["likelihood"]))), max(1, min(5, int(t["impact"])))
        risk = lik * imp
        accepted.append(Finding(rule=t["catalog_id"] if t["catalog_id"] != "NEW" else "LLM", title=t["title"], stride=t["stride"],
                                category=t["lens"], element=t["element"], element_kind="component" if t["element"] in spec.components else "flow",
                                likelihood=lik, impact=imp, risk=risk,
                                rating="critical" if risk >= 20 else "high" if risk >= 12 else "medium" if risk >= 6 else "low",
                                threat=t["threat"], recommendation=t["recommendation"], source="llm"))
    return accepted, rejected


def augment(raw: dict, api_key: str | None = None, n: int = 8) -> dict:
    key = api_key or os.environ.get("GEMINI_API_KEY", "")
    spec, kb = model.load(raw), engine.load_kb()
    findings = engine.review(spec, kb)
    if not key:
        return dict(mode="rules_only", findings=[asdict(f) for f in findings], llm=[], rejected=[])
    extra, rejected = guard(_call(_prompt(raw, kb, findings, n), key), spec, kb, findings)
    return dict(mode="rules+llm", findings=[asdict(f) for f in findings], llm=[asdict(f) for f in extra], rejected=rejected)


def bench_llm(api_key: str, sample: int = 40, seed: int = 7, pause_s: float = 7.0) -> dict:
    """The model alone, without rule findings: does it raise the seeded flaw on the right element?"""
    kb = engine.load_kb()
    muts = bench.mutations()
    random.Random(seed).shuffle(muts)
    by_rule, picked = {}, []
    for name, m in muts:  # stratify: at most 2 cases per expected rule
        if by_rule.get(m.expected_rule, 0) < 2:
            by_rule[m.expected_rule] = by_rule.get(m.expected_rule, 0) + 1
            picked.append((name, m))
    picked = picked[:sample]
    rows = []
    for name, m in picked:
        spec = model.load(m.spec)
        t0 = time.time()
        threats = _call(_prompt(m.spec, kb, None, 10), api_key)
        ok, bad = guard(threats, spec, kb, [])
        exact = any(f.rule == m.expected_rule and f.element == m.element for f in ok)
        concept = any(f.rule == m.expected_rule for f in ok)
        rows.append(dict(arch=name, op=m.op, rule=m.expected_rule, element=m.element, exact=exact, concept_anywhere=concept,
                         threats=len(threats), rejected_by_guard=len(bad), latency_s=round(time.time() - t0, 1)))
        time.sleep(pause_s)
    n = len(rows)
    return dict(model=MODEL, cases=n, exact_hits=sum(r["exact"] for r in rows),
                exact_rate=round(sum(r["exact"] for r in rows) / n, 4),
                concept_rate=round(sum(r["concept_anywhere"] for r in rows) / n, 4),
                guard_rejections=sum(r["rejected_by_guard"] for r in rows), total_threats=sum(r["threats"] for r in rows), rows=rows)
