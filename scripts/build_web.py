"""Copy the engine, knowledge base, examples and benchmark results into web/ for Pages."""
import json
import shutil
from pathlib import Path

root = Path(__file__).resolve().parent.parent
web = root / "web"
py = web / "py" / "threatlens"
py.mkdir(parents=True, exist_ok=True)
for f in ["__init__.py", "model.py", "engine.py", "report.py", "bench.py", "kb.yml"]:
    shutil.copy(root / "threatlens" / f, py / f)
ex = web / "py" / "examples"
(ex / "real").mkdir(parents=True, exist_ok=True)
index = []
for p in sorted((root / "examples").glob("*.yml")) + sorted((root / "examples" / "real").glob("*.yml")):
    rel = p.relative_to(root / "examples")
    shutil.copy(p, ex / rel)
    index.append({"path": str(rel), "kind": "real" if rel.parts[0] == "real" else "reference"})
(web / "py" / "examples.json").write_text(json.dumps(index))
data = web / "data"; data.mkdir(exist_ok=True)
for f in ["bench_rules.json", "bench_llm.json"]:
    if (root / "results" / f).exists():
        shutil.copy(root / "results" / f, data / f)
print(f"web/ ready: {len(index)} examples")
