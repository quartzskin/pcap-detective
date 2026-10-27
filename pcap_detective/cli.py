from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze_file
from .parser import PcapError
from .report import to_json, to_markdown, to_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pcap-detective", description="Summarize a pcap/pcapng file offline.")
    p.add_argument("file", help="capture to read")
    p.add_argument("--format", choices=("text", "json", "markdown"), default="text", help="output format")
    p.add_argument("-o", "--output", help="write the report here instead of stdout")
    p.add_argument("--db", help="also keep the parsed packets in this SQLite file")
    p.add_argument("--force", action="store_true", help="let -o and --db overwrite existing files")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _same_file(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _check_target(path: str, args: argparse.Namespace) -> str | None:
    if _same_file(path, args.file):
        return f"refusing to overwrite the input file {path}"
    if os.path.exists(path) and not args.force:
        return f"{path} already exists (use --force to overwrite)"
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for target in (args.output, args.db):
        if target and (problem := _check_target(target, args)):
            print(f"error: {problem}", file=sys.stderr)
            return 2
    if args.output and args.db and _same_file(args.output, args.db):
        print("error: -o and --db point at the same file", file=sys.stderr)
        return 2

    db_path = args.db or ":memory:"
    try:
        summary = analyze_file(args.file, db_path)
    except (PcapError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    render = {"json": to_json, "markdown": to_markdown, "text": to_text}[args.format]
    text = render(summary)
    if args.output:
        try:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write output: {exc.strerror or exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
