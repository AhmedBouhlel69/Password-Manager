"""
SecureVault Command-Line Interface (CLI).

Allows direct, standalone terminal management of the password vault:
- Create & initialize new encrypted vault
- Add credentials with secure password generation
- List & search credentials
- Copy credentials with Win32 privacy history suppression and auto-wipe
- Run offline password health & hygiene analysis
- Check passwords against Have I Been Pwned k-anonymity API
- Import plaintext notes file via local ETL pipeline
"""

import argparse
import getpass
import os
import sys
from typing import Optional

from src.core.vault import Vault, VaultError
from src.core.clipboard import SecureClipboard
from src.breach.password_health import analyze_vault_health
from src.breach.hibp import HIBPChecker
from src.import_etl.extractor import read_notes_file, segment_notes
from src.import_etl.llm_parser import LocalLLMParser
from src.import_etl.validator import validate_candidate_entry
from src.import_etl.deduplicator import find_duplicate

from src.ble.windows_bluetooth import verify_bluetooth_2fa

def enforce_cli_2fa(vault: Vault) -> bool:
    """Check Bluetooth 2FA if trusted devices are registered. Returns True if access granted."""
    devices = vault.get_trusted_devices()
    if not devices:
        return True  # No 2FA configured
    target = devices[0]
    mac = target.get("device_id", "")
    name = target.get("device_name", "iPhone")
    print(f"\n📲 Bluetooth 2FA: Verifying presence of '{name}' ({mac})...")
    ok, msg = verify_bluetooth_2fa(mac, timeout=5.0)
    if ok:
        print(f"✅ {msg}")
        return True
    else:
        print(f"❌ 2FA FAILED: {msg}", file=sys.stderr)
        print("Session denied. Ensure your paired Bluetooth device is nearby and powered on.", file=sys.stderr)
        vault.lock()
        return False


def get_master_password(prompt: str = "Enter master password: ", confirm: bool = False) -> str:
    pwd = getpass.getpass(prompt)
    if confirm:
        pwd2 = getpass.getpass("Confirm master password: ")
        if pwd != pwd2:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    return pwd


def cmd_create(args):
    vault_path = args.vault
    if os.path.exists(vault_path):
        print(f"Error: Vault already exists at '{vault_path}'", file=sys.stderr)
        return 1

    pwd = get_master_password("Choose a strong master password: ", confirm=True)
    v = Vault()
    print(f"Deriving master key via Argon2id (64MB, 3 iterations) and creating vault...")
    v.create_vault(vault_path, pwd)
    print(f"[SUCCESS] Encrypted vault created at: {vault_path}")
    v.close()
    return 0


def cmd_add(args):
    vault_path = args.vault
    if not os.path.exists(vault_path):
        print(f"Error: Vault not found at '{vault_path}'", file=sys.stderr)
        return 1

    pwd = get_master_password()
    v = Vault()
    try:
        v.unlock(vault_path, pwd)
    except VaultError as e:
        print(f"[ERROR] Unlock failed: {e}", file=sys.stderr)
        return 1

    if not enforce_cli_2fa(v):
        return 1

    try:
        site = input("Site / Service name: ").strip()
        username = input("Username / Email: ").strip()
        url = input("URL (optional): ").strip()
        password = getpass.getpass("Password (leave blank to generate random): ").strip()

        if not password:
            import secrets
            import string
            chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            password = "".join(secrets.choice(chars) for _ in range(20))
            print("Generated a secure 20-character random password (copied to clipboard).")
            from src.core.clipboard import SecureClipboard
            SecureClipboard(timeout=60).copy_password(password)

        notes = input("Notes (optional): ").strip()

        entry_data = {
            "site": site,
            "username": username,
            "url": url,
            "password": password,
            "notes": notes,
            "tags": []
        }

        entry_id = v.add_entry(entry_data)
        print(f"[SUCCESS] Entry saved (ID: {entry_id})")
        return 0
    finally:
        v.lock()


def cmd_list(args):
    vault_path = args.vault
    if not os.path.exists(vault_path):
        print(f"Error: Vault not found at '{vault_path}'", file=sys.stderr)
        return 1

    pwd = get_master_password()
    v = Vault()
    try:
        v.unlock(vault_path, pwd)
    except VaultError as e:
        print(f"[ERROR] Unlock failed: {e}", file=sys.stderr)
        return 1

    if not enforce_cli_2fa(v):
        return 1

    try:
        entries = v.list_entries()
        if not entries:
            print("Vault is empty.")
        else:
            print(f"\n--- Vault Entries ({len(entries)}) ---")
            for idx, e in enumerate(entries, 1):
                site = e.get("site", "Unknown")
                user = e.get("username", "")
                print(f"{idx}. {site:<25} | User: {user}")
        print()
        return 0
    finally:
        v.lock()


def cmd_copy(args):
    vault_path = args.vault
    search_query = args.query

    pwd = get_master_password()
    v = Vault()
    try:
        v.unlock(vault_path, pwd)
    except VaultError as e:
        print(f"[ERROR] Unlock failed: {e}", file=sys.stderr)
        return 1

    if not enforce_cli_2fa(v):
        return 1

    try:
        matches = v.search_entries(search_query)
        if not matches:
            print(f"No entry found matching '{search_query}'.")
            return 1

        target = matches[0]
        site = target.get("site", "Unknown")
        user = target.get("username", "")
        pwd_to_copy = target.get("password", "")

        clip = SecureClipboard(timeout=30)
        clip.copy_password(pwd_to_copy)
        print(f"[SUCCESS] Password for {site} ({user}) copied to clipboard!")
        print("         (Marked with Windows Privacy flags; will auto-clear in 30 seconds)")
        import time
        print("         Waiting 30 seconds before clearing clipboard...")
        time.sleep(30)
        clip.clear_now()
        print("         Clipboard cleared.")
        return 0
    finally:
        v.lock()


def cmd_health(args):
    vault_path = args.vault
    pwd = get_master_password()
    v = Vault()
    try:
        v.unlock(vault_path, pwd)
    except VaultError as e:
        print(f"[ERROR] Unlock failed: {e}", file=sys.stderr)
        return 1

    if not enforce_cli_2fa(v):
        return 1

    try:
        entries = v.list_entries()
        report = analyze_vault_health(entries)

        print("\n================== VAULT HEALTH REPORT ==================")
        print(f"Total Entries:   {report['total_entries']}")
        print(f"Security Score:  {report['overall_score']} / 100")
        print(f"Reused Passwords: {report['reused_count']}")
        if report["reused_groups"]:
            print("\nReused groups:")
            for pwd, matched in report["reused_groups"].items():
                names = [m["site"] for m in matched]
                print(f"  - Reused across: {', '.join(names)}")

        print(f"\nWeak Passwords:  {report['weak_count']}")
        for w in report["weak_entries"]:
            print(f"  - {w['site']}: {', '.join(w['issues'])}")
        print("=========================================================\n")
        return 0
    finally:
        v.lock()


def cmd_hibp(args):
    vault_path = args.vault
    pwd = get_master_password()
    v = Vault()
    try:
        v.unlock(vault_path, pwd)
    except VaultError as e:
        print(f"[ERROR] Unlock failed: {e}", file=sys.stderr)
        return 1

    if not enforce_cli_2fa(v):
        return 1

    try:
        entries = v.list_entries()
        checker = HIBPChecker()
        print(f"\nQuerying Have I Been Pwned (k-anonymity, 5-character prefix only)...")

        breached_found = 0
        for e in entries:
            site = e.get("site", "Unknown")
            pwd_val = e.get("password", "")
            if not pwd_val:
                continue
            count = checker.check_password(pwd_val)
            if count > 0:
                print(f"  [COMPROMISED] {site:<20} - appeared in {count:,} known breaches!")
                breached_found += 1
            else:
                print(f"  [SAFE]        {site:<20} - no breach matches found.")

        print(f"\nDone. {breached_found} compromised credentials identified.")
        return 0
    finally:
        v.lock()


def cmd_import(args):
    vault_path = args.vault
    notes_file = args.notes_file
    use_ollama = args.ollama

    if not os.path.exists(notes_file):
        print(f"Error: Notes file not found at '{notes_file}'", file=sys.stderr)
        return 1

    pwd = get_master_password()
    v = Vault()
    try:
        v.unlock(vault_path, pwd)
    except VaultError as e:
        print(f"[ERROR] Unlock failed: {e}", file=sys.stderr)
        return 1

    if not enforce_cli_2fa(v):
        return 1

    try:
        print(f"\n[1/4] Reading and segmenting '{notes_file}'...")
        content = read_notes_file(notes_file)
        chunks = segment_notes(content, max_chunk_chars=2000)
        print(f"      Split into {len(chunks)} sections.")

        parser = LocalLLMParser()
        all_raw = []

        ollama_ready = use_ollama and parser.is_ollama_available()
        if ollama_ready:
            print("[2/4] Extracting credentials via Local Ollama (127.0.0.1, offline)...")
        else:
            print("[2/4] Extracting credentials via Fast Pattern Parser...")

        for i, c in enumerate(chunks, 1):
            if ollama_ready:
                raw_entries = parser.parse_chunk_with_ollama(c)
            else:
                raw_entries = parser.regex_fallback_parse(c)
            all_raw.extend(raw_entries)

        print(f"[3/4] Validating and deduplicating {len(all_raw)} candidate entries...")
        existing = v.list_entries()
        candidates = []

        for raw in all_raw:
            res = validate_candidate_entry(raw)
            if res["is_valid"]:
                cand = res["entry"]
                cand["_conf"] = res["confidence"]
                dup = find_duplicate(cand, existing)
                cand["_dup"] = dup[0]["site"] if dup else None
                candidates.append(cand)

        if not candidates:
            print("No valid credentials could be extracted from file.")
            return 0

        print(f"\nExtracted {len(candidates)} valid candidate entries:")
        print("-" * 75)
        print(f"{'#':<3} | {'Site / Service':<22} | {'Username':<22} | {'Confidence':<10} | {'Duplicate'}")
        print("-" * 75)
        for idx, c in enumerate(candidates, 1):
            site_str = (c['site'][:20] + '..') if len(c['site']) > 22 else c['site']
            user_str = (c['username'][:20] + '..') if len(c['username']) > 22 else c['username']
            dup_str = f"Yes ({c['_dup']})" if c['_dup'] else "No"
            print(f"{idx:<3} | {site_str:<22} | {user_str:<22} | {c['_conf'].upper():<10} | {dup_str}")
        print("-" * 75)

        confirm = input(f"\nImport {len(candidates)} entries into your encrypted vault? (y/n): ").strip().lower()
        if confirm != "y":
            print("Import cancelled.")
            return 0

        for c in candidates:
            v.add_entry({
                "site": c["site"],
                "username": c["username"],
                "password": c["password"],
                "notes": c.get("notes", ""),
                "tags": ["imported"]
            })

        print(f"[SUCCESS] {len(candidates)} entries imported into vault.")

        # Secure delete prompt
        shred = input(f"\nWould you like to securely shred and overwrite '{notes_file}'? (y/N): ").strip().lower()
        if shred == "y":
            from src.import_etl.secure_delete import secure_delete_file
            try:
                secure_delete_file(notes_file, confirmed=True)
                print("[SUCCESS] Plaintext notes file securely shredded (3-pass overwrite).")
            except Exception as e:
                print(f"Warning: Could not shred file: {e}", file=sys.stderr)

        return 0
    finally:
        v.lock()



def main():
    parser = argparse.ArgumentParser(description="SecureVault Password Manager CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create
    p_create = subparsers.add_parser("create", help="Create a new vault")
    p_create.add_argument("vault", help="Path for the vault file (e.g. vault.db)")

    # add
    p_add = subparsers.add_parser("add", help="Add a credential")
    p_add.add_argument("vault", help="Path to vault file")

    # list
    p_list = subparsers.add_parser("list", help="List credentials in vault")
    p_list.add_argument("vault", help="Path to vault file")

    # copy
    p_copy = subparsers.add_parser("copy", help="Copy password to secure clipboard")
    p_copy.add_argument("vault", help="Path to vault file")
    p_copy.add_argument("query", help="Site or service name to copy password for")

    # health
    p_health = subparsers.add_parser("health", help="Analyze vault password health")
    p_health.add_argument("vault", help="Path to vault file")

    # hibp
    p_hibp = subparsers.add_parser("hibp", help="Check passwords against HIBP breach database")
    p_hibp.add_argument("vault", help="Path to vault file")

    # import
    p_import = subparsers.add_parser("import", help="Import plaintext notes into vault")
    p_import.add_argument("vault", help="Path to vault file")
    p_import.add_argument("notes_file", help="Path to plaintext notes file (.txt, .md)")
    p_import.add_argument("--ollama", action="store_true", help="Use local Ollama LLM parser (offline, 127.0.0.1)")

    args = parser.parse_args()

    commands = {
        "create": cmd_create,
        "add": cmd_add,
        "list": cmd_list,
        "copy": cmd_copy,
        "health": cmd_health,
        "hibp": cmd_hibp,
        "import": cmd_import,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        sys.exit(cmd_func(args))


if __name__ == "__main__":
    main()
