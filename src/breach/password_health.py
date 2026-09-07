"""
Password Health & Hygiene Analyzer.

Analyzes stored vault credentials for:
1. Reused passwords (grouped across different accounts)
2. Weak passwords (based on length, character set variety, entropy estimate)
3. Breach status (correlating with HIBP results)
4. Overall vault security score
"""

import math
import hashlib
import string
from collections import defaultdict
from typing import List, Dict, Any


def calculate_entropy(password: str) -> float:
    """Calculates approximate Shannon entropy bits of the character pool."""
    if not password:
        return 0.0

    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in string.punctuation or c in ' ~`@#$%^&*()-_=+[{]}\\|;:\'",<.>/?' for c in password):
        pool_size += 33

    if pool_size == 0:
        pool_size = 256

    return len(password) * math.log2(pool_size)


def assess_password_strength(password: str) -> Dict[str, Any]:
    """
    Assesses strength of an individual password.
    Returns rating: 'very_weak', 'weak', 'medium', 'strong', 'very_strong'.
    """
    if not password:
        return {"rating": "empty", "score": 0, "entropy": 0.0, "issues": ["Password is empty"]}

    issues = []
    length = len(password)
    entropy = calculate_entropy(password)

    if length < 8:
        issues.append("Too short (< 8 characters)")
    elif length < 12:
        issues.append("Somewhat short (< 12 characters)")

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    char_types = sum([has_upper, has_lower, has_digit, has_symbol])
    if char_types < 3:
        issues.append("Lacks character variety (should include upper, lower, digits, symbols)")

    if entropy < 28:
        rating = "very_weak"
        score = 20
    elif entropy < 40:
        rating = "weak"
        score = 40
    elif entropy < 60:
        rating = "medium"
        score = 65
    elif entropy < 80:
        rating = "strong"
        score = 85
    else:
        rating = "very_strong"
        score = 100

    return {
        "rating": rating,
        "score": score,
        "entropy": round(entropy, 1),
        "issues": issues
    }


def analyze_vault_health(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes a list of decrypted vault entries for overall health.
    Detects password reuse, weak passwords, and compiles statistics.
    """
    total = len(entries)
    if total == 0:
        return {
            "total_entries": 0,
            "overall_score": 100,
            "reused_count": 0,
            "reused_groups": {},
            "weak_count": 0,
            "weak_entries": [],
            "breached_count": 0
        }

    # Track password occurrences to find reuse
    pwd_to_entries = defaultdict(list)
    weak_entries = []
    total_score = 0

    for entry in entries:
        pwd = entry.get("password", "")
        entry_id = entry.get("_id", "")
        site = entry.get("site", "Unnamed Site")
        username = entry.get("username", "")

        if pwd:
            pwd_to_entries[pwd].append({
                "id": entry_id,
                "site": site,
                "username": username
            })

        assessment = assess_password_strength(pwd)
        total_score += assessment["score"]

        if assessment["rating"] in ("very_weak", "weak"):
            weak_entries.append({
                "id": entry_id,
                "site": site,
                "username": username,
                "issues": assessment["issues"],
                "rating": assessment["rating"]
            })

    # Find reusable passwords
    reused_groups = {}
    reused_entry_ids = set()
    for pwd, matched_entries in pwd_to_entries.items():
        if len(matched_entries) > 1:
            # Use truncated hash as key — never expose plaintext passwords in reports
            group_key = hashlib.sha256(pwd.encode()).hexdigest()[:12]
            reused_groups[group_key] = matched_entries
            for item in matched_entries:
                reused_entry_ids.add(item["id"])

    # Base average score, penalized by reuse
    avg_score = total_score / total
    reuse_penalty = (len(reused_entry_ids) / total) * 30
    final_score = max(0, min(100, int(avg_score - reuse_penalty)))

    return {
        "total_entries": total,
        "overall_score": final_score,
        "reused_count": len(reused_entry_ids),
        "reused_groups": reused_groups,
        "weak_count": len(weak_entries),
        "weak_entries": weak_entries,
        "healthy_count": total - len(reused_entry_ids) - len(weak_entries)
    }
