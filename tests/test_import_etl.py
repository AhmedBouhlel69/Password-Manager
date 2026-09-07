import os
import socket
import pytest

from src.import_etl.extractor import read_notes_file, segment_notes
from src.import_etl.validator import validate_candidate_entry
from src.import_etl.deduplicator import calculate_similarity, find_duplicate
from src.import_etl.secure_delete import secure_delete_file
from src.import_etl.network_guard import local_only_network_guard, SecurityError
from src.import_etl.llm_parser import LocalLLMParser


def test_validator():
    good = {
        "site": "github.com",
        "username": "ahmed@example.com",
        "password": "SecurePassword123!",
        "notes": "Main work account"
    }
    res = validate_candidate_entry(good)
    assert res["is_valid"] is True
    assert res["confidence"] == "high"

    bad = {"site": "", "password": ""}
    res_bad = validate_candidate_entry(bad)
    assert res_bad["is_valid"] is False
    assert len(res_bad["warnings"]) > 0


def test_deduplicator():
    existing = [
        {"site": "GitHub", "username": "ahmed"},
        {"site": "Google Mail", "username": "ahmed@gmail.com"}
    ]

    candidate = {"site": "github.com", "username": "ahmed"}
    dup = find_duplicate(candidate, existing)
    assert dup is not None
    assert dup[0]["site"] == "GitHub"

    non_dup = {"site": "Netflix", "username": "someone_else"}
    assert find_duplicate(non_dup, existing) is None


def test_extractor_and_segmentation(tmp_path):
    note_file = tmp_path / "notes.txt"
    sample_text = "Line 1\nLine 2\n\nSection 2\nLine 3"
    note_file.write_text(sample_text, encoding="utf-8")

    content = read_notes_file(str(note_file))
    assert "Section 2" in content

    chunks = segment_notes(content, max_chunk_chars=50)
    assert len(chunks) >= 1


def test_secure_delete(tmp_path):
    f = tmp_path / "delete_me.txt"
    f.write_text("Super secret plaintext passwords!", encoding="utf-8")
    path_str = str(f)
    assert os.path.exists(path_str)

    with pytest.raises(ValueError):
        secure_delete_file(path_str, confirmed=False)

    secure_delete_file(path_str, confirmed=True, passes=2)
    assert not os.path.exists(path_str)


def test_network_guard():
    with local_only_network_guard():
        # Connecting to a remote IP should raise SecurityError
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(SecurityError):
            s.connect(("8.8.8.8", 53))


def test_regex_fallback_parser():
    raw_text = """
    Site: example.com
    User: testuser
    Password: SecretPassword!
    """
    entries = LocalLLMParser.regex_fallback_parse(raw_text)
    assert len(entries) == 1
    assert entries[0]["site"] == "example.com"
    assert entries[0]["username"] == "testuser"
    assert entries[0]["password"] == "SecretPassword!"


def test_user_structured_format():
    user_file_sample = """
Google
myaccount@gmail.com
MyStrongP@ss123 https://accounts.google.com

Instagram
+33612345678
InstaSecret2026

Personal Bank
ahmed_online
BankSecretCode#99
https://mybank.com/portal
"""
    entries = LocalLLMParser.regex_fallback_parse(user_file_sample)
    assert len(entries) == 3

    # Entry 1
    assert entries[0]["site"] == "Google"
    assert entries[0]["username"] == "myaccount@gmail.com"
    assert entries[0]["password"] == "MyStrongP@ss123"
    assert "accounts.google.com" in entries[0]["url"]

    # Entry 2: phone number
    assert entries[1]["site"] == "Instagram"
    assert entries[1]["username"] == "+33612345678"
    assert entries[1]["password"] == "InstaSecret2026"

    # Entry 3: 4 lines with URL on line 4
    assert entries[2]["site"] == "Personal Bank"
    assert entries[2]["username"] == "ahmed_online"
    assert entries[2]["password"] == "BankSecretCode#99"
    assert "mybank.com/portal" in entries[2]["url"]

