"""Tests for the scanner, mock targets, and reports."""

from promptprobe.report import render_markdown, render_terminal
from promptprobe.scanner import PromptInjectionScanner
from promptprobe.targets import HardenedAgent, VulnerableAgent


def test_vulnerable_agent_is_compromised_by_most_attacks():
    report = PromptInjectionScanner().scan(
        VulnerableAgent().respond, target_name="vuln")
    assert report.robustness_score < 50, (
        f"vulnerable mock scored {report.robustness_score}, expected < 50"
    )
    assert report.failures(), "expected at least one successful attack"


def test_hardened_agent_resists_everything():
    report = PromptInjectionScanner().scan(
        HardenedAgent().respond, target_name="hard")
    assert report.robustness_score == 100.0
    assert report.grade() == "A"
    assert not report.failures()


def test_scan_report_math():
    report = PromptInjectionScanner().scan(
        VulnerableAgent().respond, target_name="vuln")
    assert report.total == len(report.results)
    assert report.blocked + report.compromised == report.total
    assert 0.0 <= report.robustness_score <= 100.0


def test_crashing_target_does_not_kill_scan():
    def boom(_: str) -> str:
        raise RuntimeError("target exploded")

    report = PromptInjectionScanner().scan(boom, target_name="boom")
    assert report.total > 0
    assert all(r.error for r in report.results)


def test_terminal_report_mentions_score_and_failures():
    report = PromptInjectionScanner().scan(
        VulnerableAgent().respond, target_name="vuln")
    text = render_terminal(report)
    assert str(report.robustness_score) in text
    assert "Compromised by:" in text


def test_markdown_report_structure():
    report = PromptInjectionScanner().scan(
        HardenedAgent().respond, target_name="hard")
    md = render_markdown(report)
    assert md.startswith("# Prompt-Injection Scan Report")
    assert "| Category | Blocked | Total |" in md
    assert "## Attack details" in md


def test_category_filtering_flows_through_scanner():
    from promptprobe.attacks import list_attacks
    attacks = list_attacks(category="tool_hijack")
    report = PromptInjectionScanner(attacks=attacks).scan(
        VulnerableAgent().respond, target_name="vuln")
    assert report.total == len(attacks) == 2
