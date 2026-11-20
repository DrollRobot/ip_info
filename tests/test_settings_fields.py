"""Tests for ip_info's own Settings fields (src/ip_info/config/schema.py).

The template's test_config_schema.py checks the schema conventions; these
check what ip_info adds: one optional key per provider, and the database
location.
"""

from dataclasses import fields
from pathlib import Path

import platformdirs
import pytest

from ip_info.config import Settings
from ip_info.config import schema as schema_module
from ip_info.config.schema import is_optional_secret, is_secret
from ip_info.constants import API_METADATA

pytestmark = pytest.mark.unit

_KEY_SUFFIX = "_api_key"


def test_every_provider_has_an_optional_key_field() -> None:
    by_name = {f.name: f for f in fields(Settings)}
    for api_name in API_METADATA:
        f = by_name.get(api_name + _KEY_SUFFIX)
        assert f is not None, f"no {api_name}{_KEY_SUFFIX} field in Settings"
        assert is_optional_secret(f), f"{f.name} must be secret(required=False)"


def test_every_key_field_belongs_to_a_provider() -> None:
    key_fields = [f.name for f in fields(Settings) if f.name.endswith(_KEY_SUFFIX)]
    assert sorted(name.removesuffix(_KEY_SUFFIX) for name in key_fields) == sorted(API_METADATA)


def test_only_api_keys_are_secret() -> None:
    secret_fields = [f.name for f in fields(Settings) if is_secret(f)]
    assert all(name.endswith(_KEY_SUFFIX) for name in secret_fields)


def test_key_help_says_whether_the_provider_needs_it() -> None:
    by_name = {f.name: f for f in fields(Settings)}
    for api_name, metadata in API_METADATA.items():
        help_text = str(by_name[api_name + _KEY_SUFFIX].metadata["help"])
        expected = "skipped without one" if metadata["requires_key"] else "works without one"
        assert expected in help_text, f"{api_name}: {help_text!r}"


def test_default_db_path_is_in_the_user_data_folder(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[str, object, bool]] = []

    def fake_user_data_dir(appname: str, appauthor: object, roaming: bool) -> str:
        calls.append((appname, appauthor, roaming))
        return str(tmp_path)

    monkeypatch.setattr(platformdirs, "user_data_dir", fake_user_data_dir)
    assert schema_module.default_db_path() == str(tmp_path / "ip_info.db")
    assert calls == [("ip_info", False, False)]  # local, not roaming, profile folder
    assert Settings().db_path == str(tmp_path / "ip_info.db")  # the field's default
