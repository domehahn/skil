#!/usr/bin/env python3
"""
Generate or verify the auto-generated section of external-control-crosswalk.md
from properties.yaml.

Usage:
    python3 generate_crosswalk.py                          # print table to stdout
    python3 generate_crosswalk.py --check <path>            # exit 1 if auto-gen section differs
"""

import argparse
import os
import sys
import yaml


HERE = os.path.dirname(os.path.abspath(__file__))
PROPERTIES = os.path.join(HERE, "properties.yaml")


def load_properties(path: str) -> list[dict]:
    with open(path) as f:
        data = yaml.safe_load(f)
    return data["properties"]


def analyzer_for(fixture: dict) -> str:
    """Mirror compat_test.go analyzerLabel exactly."""
    rules = fixture.get("skil_rules", [])
    for r in rules:
        if "MCP" in r:
            return "MCP"
    if "TAINT" in " ".join(rules):
        return "Taint"
    for r in rules:
        if r.startswith("SKIL-PY-") or r.startswith("SKIL-SH-"):
            return "Code / AST"
    for r in rules:
        if "BOUNDARY" in r or "SSRF" in r:
            return "Boundary"
    for r in rules:
        if r.startswith("SKIL-RESOURCE"):
            return "Pattern / Code"
        if r.startswith("SKIL-TRIGGER"):
            return "Pattern / Structured"
    return "Pattern"


def external_label(fixture: dict) -> str:
    ext = fixture.get("external_rule", "")
    variant = fixture.get("external_variant", "")
    suite = fixture.get("suite", "static")
    label = ext
    if variant:
        label = f"{ext} · {variant}"
    if suite == "semantic":
        label += " (semantic)"
    elif suite == "provider":
        label += " (provider)"
    return label


def generate_table(properties: list[dict]) -> str:
    lines = [
        "| ASP Property | External ID | Reference behavior | Native equivalent | Coverage | Analyzer | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    entries = []
    for prop in properties:
        for fixture in prop["fixtures"]:
            note = fixture.get("notes", "")
            if fixture.get("status_note"):
                note = (note + " " if note else "") + fixture["status_note"]
            entries.append({
                "asp": prop["id"],
                "base": fixture["external_rule"],
                "ext": external_label(fixture),
                "behavior": fixture["description"],
                "natives": ", ".join(fixture["skil_rules"]),
                "status": fixture.get("status", ""),
                "analyzer": analyzer_for(fixture),
                "notes": note,
            })
    entries.sort(key=lambda e: (e["asp"], e["base"]))
    for e in entries:
        lines.append(f"| {e['asp']} | {e['ext']} | {e['behavior']} | `{e['natives']}` | {e['status']} | {e['analyzer']} | {e['notes']} |")
    return "\n".join(lines) + "\n"


def extract_auto_section(filepath: str):
    """Extract the auto-generated table section from the crosswalk file."""
    with open(filepath) as f:
        lines = f.readlines()

    start = end = -1
    for i, line in enumerate(lines):
        if line.strip() == "## Auto-generated (properties.yaml)":
            start = i
        elif start >= 0 and line.strip() == "## Manually maintained":
            end = i
            break

    if start < 0 or end < 0:
        return None

    # Return lines from start to end (inclusive of header, exclusive of manual section)
    return "".join(lines[start:end]).rstrip("\n") + "\n"


def generate_auto_section(properties: list[dict]) -> str:
    header = "## Auto-generated (properties.yaml)\n\n"
    return header + generate_table(properties)


def main():
    parser = argparse.ArgumentParser(description="Generate external control crosswalk")
    parser.add_argument("--check", help="Check file auto-gen section matches (exit 1 if differs)")
    args = parser.parse_args()

    properties = load_properties(PROPERTIES)
    generated = generate_auto_section(properties)

    if args.check:
        existing = extract_auto_section(args.check)
        if existing is None:
            print(f"Error: could not find '## Auto-generated' section in {args.check}", file=sys.stderr)
            sys.exit(1)
        if existing != generated:
            print(f"Error: auto-generated section in {args.check} is out of date.", file=sys.stderr)
            print("Regenerate with: python3 compat/external-scanner/generate_crosswalk.py --check <path>", file=sys.stderr)
            sys.exit(1)
        print("Auto-generated crosswalk section is up to date.")
    else:
        print(generated, end="")


if __name__ == "__main__":
    main()
