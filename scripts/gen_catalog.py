"""Regenerate docs/catalog.md from threatlens/kb.yml."""
from pathlib import Path

from threatlens.engine import load_kb

root = Path(__file__).resolve().parent.parent
kb = load_kb()
out = ["# Threat catalog", "", f"{len(kb)} rules, generated from `threatlens/kb.yml`.", "",
       "| ID | Threat | STRIDE | Lens | Applies to | References |", "|---|---|---|---|---|---|"]
for r in kb:
    refs = " · ".join(x for x in (r.get("cwe", ""), r.get("capec", ""), r.get("attack", "")) if x)
    out.append(f"| {r['id']} | {r['title']} | {r['stride']} | {r['category']} | {r['applies_to']} | {refs} |")
for r in kb:
    out += ["", f"## {r['id']}: {r['title']}", "", f"**When:** `{r['when']}`", "", f"**Threat:** {r['threat'].strip()}", "",
            f"**Recommendation:** {r['recommendation'].strip()}"]
(root / "docs" / "catalog.md").write_text("\n".join(out) + "\n")
print("wrote docs/catalog.md")
