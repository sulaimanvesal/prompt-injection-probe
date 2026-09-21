"""CLI: ``python -m promptprobe scan --target vulnerable|hardened``."""

from __future__ import annotations

import argparse
import sys

from .report import render_markdown, render_terminal
from .scanner import PromptInjectionScanner
from .targets import make_hardened_target, make_vulnerable_target

TARGETS = {
    "vulnerable": ("vulnerable-agent (mock)", make_vulnerable_target),
    "hardened": ("hardened-agent (mock)", make_hardened_target),
}


def _progress(result) -> None:
    mark = "❌" if result.compromised else "✅"
    print(f"  {mark} {result.attack.id}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="promptprobe",
        description="Probe an agent's resistance to prompt-injection attacks.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run the attack battery against a target.")
    scan.add_argument("--target", choices=sorted(TARGETS), default="vulnerable",
                      help="Built-in mock target to scan.")
    scan.add_argument("--report", metavar="PATH",
                      help="Write a Markdown report to PATH.")
    scan.add_argument("--category", default=None,
                      help="Only run attacks in this category.")

    args = parser.parse_args(argv)

    if args.command == "scan":
        from .attacks import list_attacks
        name, factory = TARGETS[args.target]
        attacks = list_attacks(category=args.category) if args.category else None
        if args.category and not attacks:
            print(f"Unknown category: {args.category}", file=sys.stderr)
            return 2
        scanner = PromptInjectionScanner(attacks=attacks)
        report = scanner.scan(factory(), target_name=name, on_result=_progress)
        print()
        print(render_terminal(report))
        if args.report:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(report))
            print(f"\nMarkdown report written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
