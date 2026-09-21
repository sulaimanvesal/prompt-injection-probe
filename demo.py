"""Zero-API-key demo: scan the vulnerable and hardened mock agents side by side.

Run:  python demo.py
"""

from promptprobe.report import render_terminal
from promptprobe.scanner import PromptInjectionScanner
from promptprobe.targets import make_hardened_target, make_vulnerable_target


def main() -> None:
    scanner = PromptInjectionScanner()

    print("=" * 60)
    print("Scanning VULNERABLE agent (no injection defenses)...")
    print("=" * 60)
    vuln = scanner.scan(make_vulnerable_target(), target_name="vulnerable-agent (mock)")

    print()
    print("=" * 60)
    print("Scanning HARDENED agent (defense-in-depth)...")
    print("=" * 60)
    hard = scanner.scan(make_hardened_target(), target_name="hardened-agent (mock)")

    print()
    print("#" * 60)
    print("SUMMARY")
    print("#" * 60)
    print(render_terminal(vuln))
    print()
    print(render_terminal(hard))
    print()
    print(f"Defenses improved robustness from {vuln.robustness_score} "
          f"to {hard.robustness_score}.")


if __name__ == "__main__":
    main()
