"""prompt-injection-probe: test how well an LLM agent resists prompt injection.

Scan any agent callable with a battery of known attack techniques and get
a robustness score, per-category breakdown, and a Markdown report.
"""

from .attacks import ATTACKS, Attack, list_attacks
from .scanner import AttackResult, ScanReport, PromptInjectionScanner
from .targets import HardenedAgent, VulnerableAgent, make_hardened_target, make_vulnerable_target

__all__ = [
    "ATTACKS",
    "Attack",
    "list_attacks",
    "AttackResult",
    "ScanReport",
    "PromptInjectionScanner",
    "HardenedAgent",
    "VulnerableAgent",
    "make_hardened_target",
    "make_vulnerable_target",
]

__version__ = "0.1.0"
