import copy
import json
from pathlib import Path

import pytest
import yaml

from threatlens import bench, engine, llm, model, report

EX = Path(__file__).resolve().parent.parent / "examples"
BASE = yaml.safe_load((EX / "smart_home_cloud.yml").read_text())


def review(raw):
    return engine.review(model.load(raw))


def test_kb_is_well_formed():
    kb = engine.load_kb()
    assert len(kb) >= 30
    for r in kb:
        assert r["stride"] in llm.STRIDE and r["category"] in llm.LENSES, r["id"]
        assert r["applies_to"] in ("component", "flow", "system")
        assert r["recommendation"] and r["threat"]


@pytest.mark.parametrize("name", ["smart_home_cloud", "wearable_sync", "device_enrollment", "mobile_carrier"])
def test_hardened_baselines_are_clean(name):
    assert review(yaml.safe_load((EX / f"{name}.yml").read_text())) == []


def test_plaintext_and_unauthenticated_flow():
    raw = copy.deepcopy(BASE)
    f = next(x for x in raw["flows"] if x["id"] == "f_app_api")
    f["protocol"], f["auth"] = "http", "none"
    got = {(x.rule, x.element) for x in review(raw)}
    assert {("TL-T01", "f_app_api"), ("TL-S01", "f_app_api")} <= got


def test_same_zone_flow_is_not_a_boundary_crossing():
    raw = copy.deepcopy(BASE)
    raw["flows"].append({"id": "f_same", "from": "user_db", "to": "clip_store", "protocol": "sql", "auth": "none"})
    assert not [x for x in review(raw) if x.element == "f_same"]


def test_internet_exposure_raises_risk():
    raw = copy.deepcopy(BASE)
    dev = next(c for c in raw["components"] if c["id"] == "device_service")
    dev["controls"].remove("authz")
    internal = next(x for x in review(raw) if x.rule == "TL-E04")
    dev["internet_facing"] = True
    exposed = next(x for x in review(raw) if x.rule == "TL-E04")
    assert exposed.risk > internal.risk


def test_accepted_risk_is_reported_but_not_open():
    raw = copy.deepcopy(BASE)
    next(x for x in raw["flows"] if x["id"] == "f_app_api")["auth"] = "none"
    raw["accepted_risks"] = [{"rule": "TL-S01", "element": "f_app_api", "reason": "public status page"}]
    f = [x for x in review(raw) if x.rule == "TL-S01"][0]
    assert f.status == "accepted" and report.summary(review(raw))["open"] == 0


@pytest.mark.parametrize("patch,msg", [
    ({"zones": {}}, "zones"),
    ({"components": [{"id": "x", "type": "spaceship", "zone": "app"}]}, "unknown type"),
    ({"flows": [{"id": "f", "from": "nope", "to": "user_db", "protocol": "https", "auth": "none"}]}, "endpoints"),
])
def test_invalid_specs_are_rejected(patch, msg):
    raw = {**copy.deepcopy(BASE), **patch}
    with pytest.raises(model.SpecError, match=msg):
        model.load(raw)


def test_benchmark_rules_detect_every_seeded_flaw():
    r = bench.score_rules()
    assert r["mutations"] >= 150 and r["detection_rate"] == 1.0
    assert all(v == 0 for v in r["baseline_findings"].values())


def test_sarif_is_valid_shape():
    raw = copy.deepcopy(BASE)
    next(x for x in raw["flows"] if x["id"] == "f_app_api")["protocol"] = "http"
    spec = model.load(raw)
    s = json.loads(report.to_sarif(spec, engine.review(spec)))
    assert s["version"] == "2.1.0" and s["runs"][0]["results"]
    ids = {r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in ids for r in s["runs"][0]["results"])


def test_dfd_marks_weak_edges_and_hot_components():
    raw = copy.deepcopy(BASE)
    next(x for x in raw["flows"] if x["id"] == "f_cam_dev")["protocol"] = "mqtt"
    spec = model.load(raw)
    d = report.dfd(spec, engine.review(spec))
    assert "camera -.->" in d


def test_llm_guard_rejects_bad_elements_and_duplicates():
    spec = model.load(BASE)
    raw = copy.deepcopy(BASE)
    next(x for x in raw["flows"] if x["id"] == "f_app_api")["auth"] = "none"
    findings = engine.review(model.load(raw))
    base = dict(catalog_id="NEW", title="Replay of pairing codes", stride="Spoofing", lens="abuse", likelihood=3, impact=4,
                threat="t", recommendation="r", element="device_service")
    ok, bad = llm.guard([base, {**base, "element": "made_up"}, {**base, "stride": "Magic"},
                         {**base, "element": "f_app_api", "catalog_id": "TL-S01"}, {**base, "catalog_id": "TL-ZZZ"}],
                        spec, engine.load_kb(), findings)
    assert len(ok) == 1 and ok[0].source == "llm" and len(bad) == 4


def test_cli_fail_on_gate(tmp_path):
    from threatlens.cli import main
    assert main(["review", str(EX / "smart_home_cloud.yml"), "--fail-on", "high", "--out", str(tmp_path / "r.md")]) == 0
    assert main(["review", str(EX / "real" / "fleetops_as_built.yml"), "--fail-on", "critical", "--out", str(tmp_path / "r.md")]) == 1
