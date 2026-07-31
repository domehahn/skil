#!/usr/bin/env python3
"""One-shot migration: re-key compat/external-scanner/properties.yaml to ASPS.

New schema (v2.0.0): one entry per ASPS security property (120 total), keyed by
ASP-xx.yy, carrying the registry taxonomy plus a list of gate fixtures.

Legacy properties map to ASP properties via skil_rules <-> skil_controls
intersection. Legacy properties with no intersection are mapped manually.
"""
import json
import yaml

REGISTRY = "compat/asps/asps-registry.json"
LEGACY = "compat/external-scanner/properties.yaml"
OUT = "compat/external-scanner/properties.yaml"

# Manual mappings for the 12 legacy properties whose SKIL rules do not appear
# in any ASP property's skil_controls. Based on the legacy catalog migration
# and semantic fit.
MANUAL = {
    "hidden-instructions-html": "ASP-01.06",
    "hidden-instructions-markdown": "ASP-01.06",
    "fs-enumeration": "ASP-11.05",
    "scope-creep": "ASP-01.08",
    "trigger-baiting": "ASP-02.03",
    "trigger-modification-diff": "ASP-09.06",
    "permission-pre-staging": "ASP-04.02",
    "unpinned-skill-version": "ASP-15.01",
    "context-inappropriate-capability": "ASP-02.08",
    "nl-policy-violations": "ASP-13.03",
    "narrative-deception": "ASP-13.03",
    "yara-malware-signatures": "ASP-06.08",
}

with open(REGISTRY) as f:
    reg = json.load(f)

with open(LEGACY) as f:
    legacy = yaml.safe_load(f)

props_by_id = {p["id"]: p for p in reg["properties"]}

# rule -> set of ASP ids
asp_by_rule = {}
for p in reg["properties"]:
    for c in p["skil_controls"]:
        asp_by_rule.setdefault(c, set()).add(p["id"])

# legacy prop -> sorted ASP targets
targets = {}
for p in legacy["properties"]:
    matched = set()
    for r in p.get("skil_rules", []):
        matched |= asp_by_rule.get(r, set())
    if p["id"] in MANUAL:
        matched.add(MANUAL[p["id"]])
    targets[p["id"]] = sorted(matched)

unmapped = [pid for pid, t in targets.items() if not t]
if unmapped:
    raise SystemExit(f"unmapped legacy props: {unmapped}")

# ASP id -> list of legacy props (in legacy file order)
asp_to_legacy = {pid: [] for pid in props_by_id}
for lp in legacy["properties"]:
    for aid in targets[lp["id"]]:
        asp_to_legacy[aid].append(lp["id"])

# Build new manifest
out = []
for asp in reg["properties"]:
    entry = {
        "id": asp["id"],
        "name": asp["name"],
        "domain_id": asp["domain_id"],
        "domain": asp["domain"],
        "invariant": asp["invariant"],
        "detection": asp["detection"],
        "minimum_evidence": asp["minimum_evidence"],
        "owasp_agentic": asp["owasp_agentic"],
        "owasp_llm": asp["owasp_llm"],
        "mitre_atlas": asp["mitre_atlas"],
        "skil_controls": asp["skil_controls"],
        "skil_status": asp["skil_status"],
        "fixtures": [],
    }
    for lid in asp_to_legacy[asp["id"]]:
        lp = next(x for x in legacy["properties"] if x["id"] == lid)
        fx = {
            "fixture": lp["fixture"],
            "description": lp.get("description", ""),
            "skil_rules": lp["skil_rules"],
            "external_rule": lp.get("external_rule", ""),
            "external_rules": lp.get("external_rules", []),
            "suite": lp.get("suite", "static"),
            "status": lp.get("status", ""),
            "notes": lp.get("notes", ""),
        }
        if lp.get("external_variant"):
            fx["external_variant"] = lp["external_variant"]
        if lp.get("scan_args"):
            fx["scan_args"] = lp["scan_args"]
        if lp.get("status_note"):
            fx["status_note"] = lp["status_note"]
        entry["fixtures"].append(fx)
    out.append(entry)

manifest = {
    "schema_version": "2.0.0",
    "source_specification": "ASPS v1.0",
    "registry": "../asps/asps-registry.json",
    "properties": out,
}

with open(OUT, "w") as f:
    yaml.safe_dump(manifest, f, sort_keys=False, allow_unicode=True, width=120)

print(f"wrote {len(out)} properties to {OUT}")
print("fixture counts:", sorted({asp['id']: len(asp['fixtures']) for asp in out}.items(), key=lambda x: x[0])[:5], "...")
total = sum(len(asp['fixtures']) for asp in out)
print("total fixture entries:", total)
