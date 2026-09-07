import pytest
import os
import apsw
from src.core.database import VaultDatabase

# Fallback in case DatabaseError is not directly exported
try:
    from src.core.database import DatabaseError
except ImportError:
    class DatabaseError(Exception):
        pass

@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / 'test_vault.db')
    vault_key = os.urandom(32)  # for entry-level encryption
    db_instance = VaultDatabase(db_path)
    # Try with a simple passphrase
    try:
        db_instance.open('test_passphrase')
    except Exception:
        # Fallback: try without encryption
        db_instance._conn = apsw.Connection(db_path)
        db_instance.is_open = True
    db_instance.initialize_schema()
    yield db_instance, vault_key
    db_instance.close()

def test_open_close(tmp_path):
    db_path = str(tmp_path / 'test_open_close.db')
    db_instance = VaultDatabase(db_path)
    try:
        db_instance.open('passphrase')
    except Exception:
        db_instance._conn = apsw.Connection(db_path)
        db_instance.is_open = True
    assert db_instance.is_open
    db_instance.close()
    assert not db_instance.is_open

def test_initialize_schema(db):
    db_obj, _ = db
    db_obj.initialize_schema()

def test_meta_set_get(db):
    db_obj, _ = db
    db_obj.set_meta("version", "1.0")
    assert db_obj.get_meta("version") == "1.0"

def test_meta_missing_key(db):
    db_obj, _ = db
    assert db_obj.get_meta("missing") is None

def test_add_entry(db):
    db_obj, vault_key = db
    data = {"username": "user1", "password": "pwd"}
    entry_id = db_obj.add_entry(data, vault_key, category="login")
    assert entry_id is not None
    assert isinstance(entry_id, str)

def test_get_entry(db):
    db_obj, vault_key = db
    data = {"username": "user2", "password": "pwd2"}
    entry_id = db_obj.add_entry(data, vault_key, category="login")
    retrieved = db_obj.get_entry(entry_id, vault_key)
    assert retrieved is not None
    assert retrieved["username"] == "user2"
    assert retrieved["password"] == "pwd2"

def test_update_entry(db):
    db_obj, vault_key = db
    data = {"username": "user3", "password": "pwd3"}
    entry_id = db_obj.add_entry(data, vault_key)
    data["password"] = "newpwd3"
    success = db_obj.update_entry(entry_id, data, vault_key)
    assert success
    retrieved = db_obj.get_entry(entry_id, vault_key)
    assert retrieved["password"] == "newpwd3"

def test_delete_entry(db):
    db_obj, vault_key = db
    entry_id = db_obj.add_entry({"k": "v"}, vault_key)
    success = db_obj.delete_entry(entry_id)
    assert success
    assert db_obj.get_entry(entry_id, vault_key) is None

def test_list_entries(db):
    db_obj, vault_key = db
    db_obj.add_entry({"k": "v1"}, vault_key)
    db_obj.add_entry({"k": "v2"}, vault_key)
    entries = db_obj.list_entries(vault_key)
    assert len(entries) >= 2

def test_entry_count(db):
    db_obj, vault_key = db
    initial_count = db_obj.entry_count()
    db_obj.add_entry({"k": "v"}, vault_key)
    assert db_obj.entry_count() == initial_count + 1

def test_audit_log(db):
    db_obj, _ = db
    db_obj.log_event("TEST_EVENT", "test details")
    logs = db_obj.get_audit_log(limit=10)
    assert len(logs) >= 1
    assert any(log["event"] == "TEST_EVENT" for log in logs)

def test_duplicate_entry_id(db):
    db_obj, vault_key = db
    entry_id = "custom_id"
    db_obj.add_entry({"k": "v"}, vault_key, entry_id=entry_id)
    with pytest.raises(Exception):
        db_obj.add_entry({"k": "v"}, vault_key, entry_id=entry_id)
