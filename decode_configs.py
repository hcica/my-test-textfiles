#!/usr/bin/env python3
"""
Utility to decode the obfuscated V2Ray config strings stored in this repo.

The upstream data replaces certain characters with multi-character glyphs to
discourage copying. A V2Ray client, however, expects the canonical URI
formats (e.g. `vmess://` with Base64 payload, or plain VLESS/Trojan URLs).

This script restores the original characters so you can import the configs
directly into any V2Ray-compatible application.

When run without arguments it scans `./V2ray/*.json`, decodes every entry,
and writes plain-text copies to `./decoded/<name>.txt` for quick copy/paste.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, List

# Replacement tokens sorted by descending length so longer tokens match first.
_REPLACEMENTS: List[tuple[str, str]] = sorted(
    {
        "W*E*3)": "/",   # custom scheme separator
        "+*/^&&^#%^&": "F",
        "@-^#=-+": "2",
        "+#()-_$`": "d",
        "+#$-*=": "t",
        "&*/;(": "g",
        "?[@=#+": "b",
        "@~#.%": "h",
        "#-=&,:": "0",
        "-$%^^&": "4",
    }.items(),
    key=lambda item: -len(item[0]),
)


def decode_string(value: str) -> str:
    """Apply all token replacements to a single config string."""
    decoded = value
    for token, replacement in _REPLACEMENTS:
        decoded = decoded.replace(token, replacement)
    return decoded


def decode_file(path: Path) -> list:
    """Load a JSON config list and decode every `v2ray` entry."""
    try:
        data = json.loads(path.read_text())
    except Exception as exc:  # pragma: no cover - CLI error path
        raise SystemExit(f"Failed to read {path}: {exc}")

    if not isinstance(data, list):
        raise SystemExit(f"{path} does not contain a JSON array.")

    for entry in data:
        if isinstance(entry, dict) and "v2ray" in entry:
            entry["v2ray"] = decode_string(entry["v2ray"])
    return data


def write_json(path: Path, data: list) -> None:
    """Write JSON with a trailing newline to keep git diffs tidy."""
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def print_configs(path: Path, data: list) -> None:
    """Pretty-print decoded configs for quick copy/paste."""
    print(f"# {path}")  # noqa: T201 (print is intended for CLI output)
    for index, entry in enumerate(data):
        base = entry.get("base", "unknown")
        v2ray = entry.get("v2ray", "")
        print(f"[{index}] {base}: {v2ray}")
    print()


def write_txt(path: Path, data: list) -> None:
    """Write decoded configs to a plain-text file, one per line."""
    lines = []
    for entry in data:
        v2ray = entry.get("v2ray")
        if isinstance(v2ray, str) and v2ray:
            lines.append(v2ray)
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def decode_from_stdin() -> None:
    payload = sys.stdin.read()
    cleaned = decode_string(payload.rstrip("\n"))
    print(cleaned)


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="JSON files to decode (expects a list of config objects).",
    )
    parser.add_argument(
        "--string",
        help="Decode a single config string (takes precedence over files).",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read a single config string from STDIN.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Rewrite the provided JSON files in place with decoded strings.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Write decoded JSON files to this directory instead of stdout.",
    )
    parser.add_argument(
        "--txt-dir",
        type=Path,
        help="Write decoded configs to plain-text files in the given directory.",
    )

    args = parser.parse_args(argv)

    if args.string:
        print(decode_string(args.string))
        return

    if args.stdin:
        decode_from_stdin()
        return

    txt_dir = args.txt_dir
    files: List[Path] = list(args.files)

    if not files:
        v2ray_dir = Path("V2ray")
        if not v2ray_dir.is_dir():
            parser.error("No files provided and ./V2ray directory not found.")
        files = sorted(
            p for p in v2ray_dir.glob("*.json") if p.name.lower() != "keys.json"
        )
        if not files:
            parser.error("No .json files found under ./V2ray to decode.")
        if txt_dir is None:
            txt_dir = Path("decoded")

    output_dir = args.output_dir
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
    if txt_dir:
        txt_dir.mkdir(parents=True, exist_ok=True)

    for path in files:
        try:
            data = decode_file(path)
        except SystemExit as exc:
            if args.files:
                raise
            print(f"Skipping {path}: {exc}", file=sys.stderr)  # noqa: T201
            continue

        if args.write:
            write_json(path, data)
        if output_dir:
            write_json(output_dir / path.name, data)
        if txt_dir:
            write_txt(txt_dir / f"{path.stem}.txt", data)
        if not (args.write or output_dir or txt_dir):
            print_configs(path, data)


if __name__ == "__main__":
    main()
