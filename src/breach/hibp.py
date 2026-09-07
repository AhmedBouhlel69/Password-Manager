"""
Have I Been Pwned (HIBP) Pwned Passwords API integration.

Uses the k-anonymity model:
1. Encodes password in UTF-8, computes uppercase SHA-1 hash.
2. Sends ONLY the first 5 characters (20 bits) of the hash to api.pwnedpasswords.com.
   The remaining 35 characters NEVER leave the local machine.
3. HIBP returns all hash suffixes matching that 5-char prefix.
4. Local lookup checks if our suffix appears in the response and extracts breach count.
5. Sends 'Add-Padding: true' header so response length doesn't leak prefix data.
"""

import hashlib
import time
from typing import Optional, Dict
import httpx


class HIBPError(Exception):
    """Exception raised for errors during HIBP API calls."""
    pass


class HIBPChecker:
    """Checks password exposure against Have I Been Pwned via k-Anonymity."""

    BASE_URL = "https://api.pwnedpasswords.com/range"

    def __init__(self, user_agent: str = "SecureVaultPasswordManager/1.0", timeout: float = 10.0):
        self.headers = {
            "User-Agent": user_agent,
            "Add-Padding": "true",  # Prevent traffic-analysis based on response byte length
        }
        self.timeout = timeout

    def check_password(self, password: str, max_retries: int = 3) -> int:
        """
        Check if a password has been compromised in known data breaches.

        Args:
            password: The plaintext password (hashed locally, never sent).
            max_retries: Retry attempts on network/rate limit issues.

        Returns:
            breach_count: Number of times this password appeared in known breaches.
                          0 means unbreached / not found.
        """
        if not password:
            return 0

        # Step 1: Compute local SHA-1 hex in uppercase
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"{self.BASE_URL}/{prefix}"

        with httpx.Client(timeout=self.timeout, headers=self.headers) as client:
            for attempt in range(max_retries):
                try:
                    response = client.get(url)
                    if response.status_code == 200:
                        return self._parse_suffix_count(response.text, suffix)
                    elif response.status_code == 429:
                        retry_after = int(response.headers.get("Retry-After", 2))
                        time.sleep(retry_after)
                        continue
                    else:
                        response.raise_for_status()
                except httpx.RequestError as exc:
                    if attempt == max_retries - 1:
                        raise HIBPError(f"Network error querying HIBP: {exc}") from exc
                    time.sleep(1.0 * (attempt + 1))

        return 0

    async def check_password_async(self, password: str, client: Optional[httpx.AsyncClient] = None) -> int:
        """
        Asynchronous check for GUI / background worker use.
        """
        if not password:
            return 0

        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"{self.BASE_URL}/{prefix}"

        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=self.timeout, headers=self.headers)
            should_close = True

        try:
            response = await client.get(url)
            if response.status_code == 200:
                return self._parse_suffix_count(response.text, suffix)
            elif response.status_code == 429:
                return -1  # Rate limited signal
            else:
                response.raise_for_status()
                return 0
        finally:
            if should_close:
                await client.aclose()

    @staticmethod
    def _parse_suffix_count(response_text: str, target_suffix: str) -> int:
        """Parses HIBP range response lines (SUFFIX:COUNT) matching target_suffix."""
        target_suffix_upper = target_suffix.upper()
        for line in response_text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            ret_suffix, count_str = line.split(":", 1)
            if ret_suffix.strip().upper() == target_suffix_upper:
                try:
                    return int(count_str.strip())
                except ValueError:
                    return 0
        return 0
