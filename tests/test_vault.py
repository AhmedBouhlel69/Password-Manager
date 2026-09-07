import pytest
import os
from src.core.vault import Vault, VaultError

@pytest.fixture
def vault_path(tmp_path):
    return str(tmp_path / 'test_vault.vault')

def test_create_vault(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    assert v.state == "unlocked"

def test_create_vault_file_exists(vault_path):
    v1 = Vault()
    v1.create_vault(vault_path, "master123")
    v2 = Vault()
    with pytest.raises(VaultError):
        v2.create_vault(vault_path, "master456")

def test_unlock_vault(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    v.lock()
    assert v.state == "locked"
    success = v.unlock(vault_path, "master123")
    assert success
    assert v.state == "unlocked"

def test_unlock_wrong_password(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    v.lock()
    with pytest.raises(VaultError):
        v.unlock(vault_path, "wrong_password")

def test_lock_vault(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    v.lock()
    assert v.state == "locked"

def test_add_and_get_entry(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    data = {"title": "My Site", "username": "user", "password": "pwd"}
    entry_id = v.add_entry(data, category="login")
    retrieved = v.get_entry(entry_id)
    assert retrieved is not None
    assert retrieved["title"] == "My Site"
    assert retrieved["password"] == "pwd"

def test_update_entry(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    entry_id = v.add_entry({"k": "v"})
    success = v.update_entry(entry_id, {"k": "v2"})
    assert success
    assert v.get_entry(entry_id)["k"] == "v2"

def test_delete_entry(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    entry_id = v.add_entry({"k": "v"})
    success = v.delete_entry(entry_id)
    assert success
    assert v.get_entry(entry_id) is None

def test_list_entries(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    v.add_entry({"k": "1"})
    v.add_entry({"k": "2"})
    entries = v.list_entries()
    assert len(entries) >= 2

def test_search_entries(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    v.add_entry({"site": "google.com"}, category="login")
    v.add_entry({"site": "yahoo.com"}, category="login")
    entries = v.list_entries()
    assert len(entries) == 2
    # In lieu of a direct search method on Vault, 
    # we filter the list of entries to simulate search validation.
    filtered = [e for e in entries if e.get("site") == "google.com"]
    assert len(filtered) == 1

def test_operations_when_locked(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    v.lock()
    with pytest.raises(VaultError):
        v.add_entry({"k": "v"})
    with pytest.raises(VaultError):
        v.get_entry("some_id")

def test_close_vault(vault_path):
    v = Vault()
    v.create_vault(vault_path, "master123")
    v.close()
    assert v.state == "closed"
