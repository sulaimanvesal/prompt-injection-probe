"""Terminal and Markdown rendering of scan reports."""

from __future__ import annotations

from datetime import datetime, timezone

from .scanner import ScanReport

_SEV_ICON = {"high": "🔴", "medium": "🟡"}


def render_terminal(report: ScanReport) -> str:
    lines = [
        f"Prompt-injection scan: {report.target_name}",
        f"Robustness: {report.robustness_score}/100 (grade {report.grade()}) — "
        f"{report.blocked}/{report.total} attacks blocked",
        "",
        "By category:",
    ]
    for category, stats in sorted(report.by_category().items()):
        blocked = stats["total"] - stats["compromised"]
        lines.append(f"  {category:22s} {blocked:>2}/{stats['total']} blocked")
    failures = report.failures()
    if failures:
        lines += ["", "Compromised by:"]
        for r in failures:
            icon = _SEV_ICON.get(r.attack.severity, "")
            lines.append(f"  {icon} [{r.attack.severity}] {r.attack.name} ({r.attack.id})")
    else:
        lines += ["", "No successful attacks. Target resisted the full battery."]
    return "\n".join(lines)


def render_markdown(report: ScanReport) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Prompt-Injection Scan Report",
        "",
        f"**Target:** `{report.target_name}`",
        f"**Date:** {ts}",
        f"**Robustness score:** {report.robustness_score}/100 (grade {report.grade()})",
        f"**Blocked:** {report.blocked}/{report.total} attacks",
        "",
        "## Results by category",
        "",
        "| Category | Blocked | Total |",
        "|---|---|---|",
    ]
    for category, stats in sorted(report.by_category().items()):
        blocked = stats["total"] - stats["compromised"]
        lines.append(f"| `{category}` | {blocked} | {stats['total']} |")
    lines += ["", "## Attack details", ""]
    for r in report.results:
        status = "❌ COMPROMISED" if r.compromised else "✅ blocked"
        lines += [
            f"### {r.attack.name} `{r.attack.id}` — {status}",
            "",
            f"- **Category:** {r.attack.category} · **Severity:** {r.attack.severity}",
            f"- **Technique:** {r.attack.description}",
        ]
        if r.error:
            lines.append(f"- **Error:** `{r.error}`")
        else:
            lines.append(f"- **Target response:** `{r.response_excerpt}`")
        lines.append("")
    return "\n".join(lines)
