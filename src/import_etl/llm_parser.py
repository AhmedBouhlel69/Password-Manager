"""
Local LLM-assisted Parser using Ollama.

Communicates with a local Ollama daemon (default: http://127.0.0.1:11434)
using a prompt asking for structured JSON extraction.
Runs under the local_only_network_guard to guarantee zero telemetry or external network calls.
Includes a regex-based fallback heuristic in case Ollama is not installed or unreachable.
"""

import json
import re
from typing import List, Dict, Any, Optional
import httpx

from src.import_etl.network_guard import local_only_network_guard


OLLAMA_PROMPT_TEMPLATE = """You are a specialized credential extraction engine.
Analyze the following unstructured notes text and extract all user login accounts, credentials, and passwords.

For EACH credential found, return a JSON object with:
- "site": name of the service, website, or application
- "username": username, handle, or email (if found)
- "password": the cleartext password (if found)
- "notes": any additional relevant notes, security answers, or PINs

Respond ONLY with a valid JSON array of objects. Do not include markdown code fences or conversational text.

Text to parse:
{text}
"""


class LocalLLMParser:
    def __init__(self, endpoint: str = "http://127.0.0.1:11434", model: str = "llama3.2:latest", timeout: float = 60.0):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_ollama_available(self) -> bool:
        """Checks if local Ollama daemon is reachable on 127.0.0.1."""
        try:
            with local_only_network_guard():
                resp = httpx.get(f"{self.endpoint}/api/tags", timeout=2.0)
                return resp.status_code == 200
        except Exception:
            return False

    def parse_chunk_with_ollama(self, text_chunk: str) -> List[Dict[str, Any]]:
        """
        Queries local Ollama to parse text into structured credentials.
        Guarded against any non-localhost network traffic.
        """
        prompt = OLLAMA_PROMPT_TEMPLATE.format(text=text_chunk)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }

        with local_only_network_guard():
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(f"{self.endpoint}/api/generate", json=payload)
                response.raise_for_status()
                data = response.json()
                raw_response = data.get("response", "")

                try:
                    parsed = json.loads(raw_response)
                    if isinstance(parsed, list):
                        return parsed
                    elif isinstance(parsed, dict) and "entries" in parsed:
                        return parsed["entries"]
                    elif isinstance(parsed, dict) and "credentials" in parsed:
                        return parsed["credentials"]
                    elif isinstance(parsed, dict):
                        return [parsed]
                except json.JSONDecodeError:
                    pass

        return self.regex_fallback_parse(text_chunk)

    @staticmethod
    def regex_fallback_parse(text: str) -> List[Dict[str, Any]]:
        """
        Rule-based heuristic fallback parser supporting:
        1. 3-line structured blocks (User's primary format):
           Line 1: Site / Platform / Account
           Line 2: ID / Gmail / Phone / Username
           Line 3+: Password and/or Access links
        2. Explicit key-value lines (Site: / User: / Password: / Mdp: / etc.)
        3. Single-line delimited formats (site | user | pass or CSV)
        """
        # --- Strategy 1: Natural Block Parser (separated by blank lines or separators) ---
        raw_blocks = re.split(r"\n\s*(?:\n|[-=_*]{3,}\s*\n)+", text.strip())
        block_candidates = []

        for block in raw_blocks:
            lines = [l.strip() for l in block.splitlines() if l.strip()]
            if len(lines) < 2:
                continue

            # Check if this block is 2, 3, or more lines
            # Line 1: Site / platform / account
            site_raw = lines[0]
            site = re.sub(
                r"^(?:(?:site|platform|plateforme|account|compte|nom|app|application)[\s:=]+|[-*•]\s*|\d+[\.\)]\s*)",
                "", site_raw, flags=re.IGNORECASE
            ).strip()

            # Line 2: ID / Gmail / Phone / Username
            user_raw = lines[1]
            user = re.sub(
                r"^(?:(?:id|identifiant|username|user|utilisateur|email|mail|gmail|phone|tel|téléphone|pseudo)[\s:=]+)",
                "", user_raw, flags=re.IGNORECASE
            ).strip()

            pwd = ""
            url = ""
            notes_list = []

            # Remaining lines (Line 3, 4, ...): Password and/or Access links
            for rem_line in lines[2:]:
                cleaned_rem = re.sub(
                    r"^(?:(?:password|pass|pwd|mot\s*de\s*passe|mdp|code|secret|lien|link|url)[\s:=]+)",
                    "", rem_line, flags=re.IGNORECASE
                ).strip()

                # Find any URL in this line
                url_match = re.search(r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s]*)", cleaned_rem, re.IGNORECASE)
                if url_match:
                    found_url = url_match.group(1)
                    if not url:
                        url = found_url if found_url.startswith("http") else f"https://{found_url}"
                    # Check if there is also a password on the same line
                    remainder = cleaned_rem.replace(found_url, "").strip()
                    if remainder:
                        if not pwd:
                            pwd = remainder
                        else:
                            notes_list.append(remainder)
                else:
                    if not pwd:
                        pwd = cleaned_rem
                    else:
                        notes_list.append(cleaned_rem)

            # If only 2 lines were provided, check if line 2 was password and user was empty
            if len(lines) == 2 and not pwd:
                pwd = user
                user = ""

            if site and (pwd or user):
                block_candidates.append({
                    "site": site,
                    "username": user,
                    "password": pwd,
                    "url": url,
                    "notes": "\n".join(notes_list)
                })

        # If blank-line block strategy succeeded and found entries, return them!
        if block_candidates:
            return block_candidates

        # --- Strategy 2: Consecutive 3-line blocks without blank lines ---
        all_lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("---")]
        if len(all_lines) >= 3:
            stride_candidates = []
            i = 0
            while i + 2 < len(all_lines):
                s = all_lines[i]
                u = all_lines[i+1]
                p_line = all_lines[i+2]
                
                # Check URL in p_line
                p_url = ""
                p_pwd = p_line
                url_m = re.search(r"(https?://[^\s]+|www\.[^\s]+)", p_line, re.IGNORECASE)
                if url_m:
                    p_url = url_m.group(1)
                    rem = p_line.replace(p_url, "").strip()
                    p_pwd = rem if rem else p_url

                stride_candidates.append({
                    "site": s,
                    "username": u,
                    "password": p_pwd,
                    "url": p_url,
                    "notes": ""
                })
                i += 3
            if stride_candidates:
                return stride_candidates

        # --- Strategy 3: Key-value labeled formats ---
        kw_site = re.compile(r"^(?:website|site|service|url|app|application|compte)[\s:=]+(.+)$", re.IGNORECASE)
        kw_user = re.compile(r"^(?:user|username|email|mail|login|identifiant|utilisateur|pseudo|id)[\s:=]+(.+)$", re.IGNORECASE)
        kw_pass = re.compile(r"^(?:password|pass|pwd|mot\s*de\s*passe|mdp|code|secret)[\s:=]+(.+)$", re.IGNORECASE)
        kw_url = re.compile(r"^(?:url|link|lien)[\s:=]+(.+)$", re.IGNORECASE)

        current_entry: Dict[str, Any] = {}
        kv_results = []
        for line_str in all_lines:
            m_s = kw_site.match(line_str)
            m_u = kw_user.match(line_str)
            m_p = kw_pass.match(line_str)
            m_l = kw_url.match(line_str)

            if m_s:
                if current_entry.get("site") or current_entry.get("password"):
                    kv_results.append(current_entry)
                    current_entry = {}
                current_entry["site"] = m_s.group(1).strip()
            elif m_u:
                current_entry["username"] = m_u.group(1).strip()
            elif m_p:
                current_entry["password"] = m_p.group(1).strip()
            elif m_l:
                current_entry["url"] = m_l.group(1).strip()

        if current_entry.get("site") or current_entry.get("password"):
            kv_results.append(current_entry)

        if kv_results:
            return kv_results

        return []
