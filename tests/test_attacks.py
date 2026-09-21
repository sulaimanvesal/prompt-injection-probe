"""Tests for the attack catalog."""

from promptprobe.attacks import ATTACKS, CANARY, list_attacks


def test_catalog_has_expected_size():
    assert len(ATTACKS) >= 20, "catalog should ship a real battery of attacks"


def test_attack_ids_unique():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))


def test_every_attack_has_prompt_and_check():
    for attack in ATTACKS:
        assert attack.prompt.strip(), f"{attack.id} has empty prompt"
        assert attack.severity in ("high", "medium"), f"{attack.id} bad severity"
        assert attack.category, f"{attack.id} missing category"


def test_every_attack_canary_is_detectable():
    # Sanity: the canary token itself must trip every success check,
    # otherwise a real compromise would go unnoticed.
    for attack in ATTACKS:
        assert attack.succeeded(f"Sure, here: {CANARY}"), (
            f"{attack.id}: success check misses the plain canary"
        )


def test_benign_response_is_not_a_hit():
    benign = "Hello! How can I help you with Acme Corp products today?"
    for attack in ATTACKS:
        assert not attack.succeeded(benign), f"{attack.id}: false positive"


def test_list_attacks_filters():
    highs = list_attacks(severity="high")
    assert highs and all(a.severity == "high" for a in highs)
    cats = {a.category for a in ATTACKS}
    for cat in cats:
        assert list_attacks(category=cat), f"empty category {cat}"


def test_categories_cover_known_techniques():
    cats = {a.category for a in ATTACKS}
    for expected in ("direct_override", "encoded_payload", "tool_hijack",
                     "delimiter_escape", "data_smuggling", "obfuscation"):
        assert expected in cats, f"missing technique family: {expected}"
