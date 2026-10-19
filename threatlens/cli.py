"""threatlens review ARCH.yml [--format md|json|sarif|mermaid] [--fail-on high] [--llm]
threatlens bench [--llm --sample 40]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

from . import bench, engine, llm, model, report

RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="threatlens")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("review", help="review one architecture spec")
    r.add_argument("spec")
    r.add_argument("--format", choices=["md", "json", "sarif", "mermaid"], default="md")
    r.add_argument("--out")
    r.add_argument("--fail-on", choices=list(RANK), help="exit 1 if an open finding is at or above this rating")
    r.add_argument("--llm", action="store_true", help="add Gemini-suggested threats (needs GEMINI_API_KEY)")
    b = sub.add_parser("bench", help="seeded-flaw benchmark")
    b.add_argument("--llm", action="store_true")
    b.add_argument("--sample", type=int, default=40)
    b.add_argument("--out", default="results")
    a = ap.parse_args(argv)

    if a.cmd == "review":
        raw = yaml.safe_load(Path(a.spec).read_text())
        try:
            spec = model.load(raw)
        except model.SpecError as e:
            print(f"invalid spec: {e}", file=sys.stderr)
            return 2
        findings = engine.review(spec)
        if a.llm:
            res = llm.augment(raw)
            findings += [engine.Finding(**f) for f in res["llm"]]
            findings.sort(key=lambda f: -f.risk)
        text = {"md": report.to_markdown, "json": report.to_json, "mermaid": report.dfd}[a.format](spec, findings) \
            if a.format != "sarif" else report.to_sarif(spec, findings, a.spec)
        if a.out:
            Path(a.out).write_text(text)
        else:
            print(text)
        if a.fail_on:
            worst = max((RANK[f.rating] for f in findings if f.status == "open"), default=0)
            return 1 if worst >= RANK[a.fail_on] else 0
        return 0

    out = Path(a.out); out.mkdir(exist_ok=True)
    res = bench.score_rules()
    (out / "bench_rules.json").write_text(json.dumps({k: v for k, v in res.items() if k != "rows"}, indent=2))
    print(f"rules: {res['detected']}/{res['mutations']} seeded flaws detected on the right element; baseline findings {res['baseline_findings']}")
    if a.llm:
        key = os.environ.get("GEMINI_API_KEY", "")
        if not key:
            print("GEMINI_API_KEY not set", file=sys.stderr)
            return 2
        lr = llm.bench_llm(key, a.sample)
        (out / "bench_llm.json").write_text(json.dumps(lr, indent=2))
        print(f"llm ({lr['model']}): {lr['exact_hits']}/{lr['cases']} exact, concept rate {lr['concept_rate']}, guard rejected {lr['guard_rejections']}/{lr['total_threats']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
