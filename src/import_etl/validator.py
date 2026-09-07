"""
Candidate Credential Validation & Confidence Scoring.

Sanity checks candidate credentials extracted from unstructured text:
- Checks if username looks like email / username handle
- Checks if password has reasonable length and complexity
- Checks if site looks like domain, app name, or service
- Assigns confidence score: high, medium, low
"""

import re
from typing import Dict, Any, List

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
URL_REGEX = re.compile(r"^(https?://)?([a-zA-Z0-9.-]+(\.[a-zA-Z]{2,}))(:[0-9]+)?(/.*)?$", re.IGNORECASE)
COMMON_SITES = {"google", "github", "apple", "microsoft", "amazon", "facebook", "twitter", "netflix", "spotify"}


PHONE_REGEX = re.compile(r"^\+?[0-9\s().-]{6,20}$")


def validate_candidate_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates candidate fields and assigns a confidence score.

    Returns:
        {
            "is_valid": bool,
            "confidence": "high" | "medium" | "low",
            "score": float (0.0 - 1.0),
            "warnings": List[str],
            "entry": normalized_dict
        }
    """
    site = str(entry.get("site", "")).strip()
    username = str(entry.get("username", "")).strip()
    password = str(entry.get("password", "")).strip()
    url = str(entry.get("url", "")).strip()
    notes = str(entry.get("notes", "")).strip()

    warnings: List[str] = []
    score = 0.0

    # 1. Site validation
    if not site:
        warnings.append("Missing site / service name")
    else:
        score += 0.3
        if "." in site or URL_REGEX.match(site) or site.lower() in COMMON_SITES:
            score += 0.1

    # 2. Password validation
    if not password:
        warnings.append("Missing password")
    elif len(password) < 4:
        warnings.append("Password is extraordinarily short (< 4 chars)")
        score += 0.1
    elif len(password) > 128:
        warnings.append("Password is unusually long (> 128 chars)")
        score += 0.15
    else:
        score += 0.4
        # Bonus for complexity
        has_variety = any(c.isdigit() for c in password) and any(c.isalpha() for c in password)
        if has_variety:
            score += 0.05

    # 3. Username / Email / Phone validation
    if not username:
        warnings.append("Missing username / ID")
    else:
        score += 0.15
        if EMAIL_REGEX.match(username) or PHONE_REGEX.match(username) or len(username) >= 3:
            score += 0.05

    # Determine confidence level
    if score >= 0.8:
        confidence = "high"
    elif score >= 0.5:
        confidence = "medium"
    else:
        confidence = "low"

    is_valid = bool(site and password)

    return {
        "is_valid": is_valid,
        "confidence": confidence,
        "score": round(score, 2),
        "warnings": warnings,
        "entry": {
            "site": site,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes
        }
    }
