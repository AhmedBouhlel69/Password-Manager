"""
Deduplicator for Candidate Import Entries against Existing Vault.

Uses difflib.SequenceMatcher for normalized string similarity.
"""

from difflib import SequenceMatcher
from typing import List, Dict, Any, Optional, Tuple


COMMON_TLDS = (".com", ".org", ".net", ".io", ".co", ".app", ".dev", ".edu", ".gov")


def normalize_str(s: str) -> str:
    """Normalizes string for comparison (removes protocol, lowercase, trim)."""
    s = s.lower().strip()
    for prefix in ("https://", "http://", "www."):
        if s.startswith(prefix):
            s = s[len(prefix):]
    s = s.rstrip("/")
    return s.strip()


def extract_base_and_tld(s: str) -> Tuple[str, str]:
    """Separates domain base from common TLD if present."""
    norm = normalize_str(s)
    for tld in COMMON_TLDS:
        if norm.endswith(tld):
            return norm[:-len(tld)], tld
    return norm, ""


def calculate_similarity(a: str, b: str) -> float:
    """Returns string similarity ratio between 0.0 and 1.0.

    - Exact matches return 1.0
    - Same base with one missing TLD (e.g. github.com vs GitHub) returns 0.95
    - Conflicting TLDs (e.g. example.com vs example.org) are penalized
    """
    norm_a = normalize_str(a)
    norm_b = normalize_str(b)
    if norm_a == norm_b:
        return 1.0

    base_a, tld_a = extract_base_and_tld(a)
    base_b, tld_b = extract_base_and_tld(b)

    # Conflicting TLDs should never be treated as the same service
    if tld_a and tld_b and tld_a != tld_b:
        return SequenceMatcher(None, norm_a, norm_b).ratio() * 0.6

    # Brand name vs full domain (e.g., "GitHub" vs "github.com")
    if base_a and base_b and base_a == base_b:
        return 0.95

    return SequenceMatcher(None, norm_a, norm_b).ratio()


def find_duplicate(
    candidate: Dict[str, Any],
    existing_entries: List[Dict[str, Any]],
    threshold: float = 0.80
) -> Optional[Tuple[Dict[str, Any], float]]:
    """
    Checks if a candidate entry matches an existing vault entry.
    Returns (matching_entry, similarity_score) or None.
    """
    cand_site = candidate.get("site", "")
    cand_user = candidate.get("username", "").lower().strip()

    best_match: Optional[Dict[str, Any]] = None
    best_score: float = 0.0

    for entry in existing_entries:
        existing_site = entry.get("site", "")
        existing_user = entry.get("username", "").lower().strip()

        site_sim = calculate_similarity(cand_site, existing_site)

        # If usernames both exist and match exactly, boost match
        if cand_user and existing_user:
            if cand_user == existing_user and site_sim >= threshold:
                return (entry, round(site_sim, 2))
        elif site_sim >= 0.95:
            # Near identical site name
            return (entry, round(site_sim, 2))

        if site_sim > best_score and site_sim >= threshold:
            best_score = site_sim
            best_match = entry

    if best_match and best_score >= threshold:
        return (best_match, round(best_score, 2))

    return None
