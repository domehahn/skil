#!/usr/bin/env python3
"""Check relative Markdown links without fetching remote content."""

from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def main() -> int:
    failures = []
    for source in [ROOT / "README.md", ROOT / "SECURITY.md", *sorted((ROOT / "docs").rglob("*.md"))]:
        text = source.read_text(encoding="utf-8")
        for raw in LINK.findall(text):
            target = raw.strip().split()[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            relative = unquote(parsed.path)
            candidate = (source.parent / relative).resolve()
            try:
                candidate.relative_to(ROOT)
            except ValueError:
                failures.append(f"{source.relative_to(ROOT)}: link escapes repository: {target}")
                continue
            if not candidate.exists():
                failures.append(f"{source.relative_to(ROOT)}: missing target: {target}")
    if failures:
        print("documentation link check failed:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("documentation link check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
