import pytest
from src.breach.hibp import HIBPChecker
from src.breach.password_health import calculate_entropy, assess_password_strength, analyze_vault_health


def test_parse_suffix_count():
    sample_response = """
0018A45C4D1DEF81644B54AB7F969B88D65:1
C6008F9CAB4083784CBD1874F76618D2A97:248071
0158D277C16920D7C46018A000A2D6E3BE0:384
"""
    # Matching suffix
    count = HIBPChecker._parse_suffix_count(sample_response, "C6008F9CAB4083784CBD1874F76618D2A97")
    assert count == 248071

    # Non-matching suffix
    count_missing = HIBPChecker._parse_suffix_count(sample_response, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
    assert count_missing == 0


def test_calculate_entropy():
    # Empty
    assert calculate_entropy("") == 0.0
    # Short lowercase
    ent1 = calculate_entropy("abc")
    # Long complex
    ent2 = calculate_entropy("A1!b2@C3#d4$E5%")
    assert ent2 > ent1
    assert ent2 > 60


def test_assess_password_strength():
    weak = assess_password_strength("12345")
    assert weak["rating"] in ("very_weak", "weak")
    assert len(weak["issues"]) > 0

    strong = assess_password_strength("xK9#mQ2$vL8!pZ0&wT5^")
    assert strong["rating"] in ("strong", "very_strong")


def test_analyze_vault_health_reuse():
    entries = [
        {"_id": "1", "site": "GitHub", "username": "user1", "password": "SharedPassword123!"},
        {"_id": "2", "site": "Google", "username": "user2", "password": "SharedPassword123!"},
        {"_id": "3", "site": "Bank", "username": "user3", "password": "Unique$trongP@ssw0rd!"},
    ]
    health = analyze_vault_health(entries)
    assert health["total_entries"] == 3
    assert health["reused_count"] == 2
    assert "SharedPassword123!" not in health["reused_groups"]  # C5 fix: plaintext not leaked
    assert len(health["reused_groups"]) == 1
    group = list(health["reused_groups"].values())[0]
    assert len(group) == 2
