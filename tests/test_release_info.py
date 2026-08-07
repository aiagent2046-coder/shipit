"""Tests for release labelling: app/release_info.py and GET /version.

Two properties are under test:

  * a version probe can never take the API down — every corrupt-input case
    below must degrade to nulls rather than raise;
  * the additive labels must not disturb `release`/`environment`, which are
    an existing invariant shared with every JSON log record.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import release_info as release_info_module
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_release_cache():
    """release_labels() is lru_cached for the process lifetime, so a test that
    changed the metadata would otherwise leak into the next one."""
    release_info_module.release_labels.cache_clear()
    yield
    release_info_module.release_labels.cache_clear()


def write_metadata(tmp_path, monkeypatch, payload) -> None:
    """Point the module at a fake release root containing `payload`."""
    if payload is not None:
        target = tmp_path / release_info_module.METADATA_FILE
        target.write_text(
            payload if isinstance(payload, str) else json.dumps(payload),
            encoding="utf-8",
        )

    monkeypatch.setattr(release_info_module, "_RELEASE_ROOT", tmp_path)


def test_reports_labels_from_a_built_release(tmp_path, monkeypatch):
    write_metadata(
        tmp_path,
        monkeypatch,
        {
            "git_sha": "a" * 40,
            "git_ref": "v2026.08.07-1",
            "git_describe": "v2026.08.07-1",
            "built_at": "2026-08-07T10:00:00+00:00",
            "source_repository": "/srv/shipit/repo",
        },
    )

    assert release_info_module.release_labels() == {
        "version": "v2026.08.07-1",
        "built_at": "2026-08-07T10:00:00+00:00",
    }


def test_source_checkout_reports_nulls_rather_than_failing(
    tmp_path, monkeypatch
):
    # No metadata file at all: the development and test case.
    write_metadata(tmp_path, monkeypatch, None)

    assert release_info_module.release_labels() == {
        "version": None,
        "built_at": None,
    }


def test_corrupt_metadata_degrades_to_nulls(tmp_path, monkeypatch):
    write_metadata(tmp_path, monkeypatch, "{not valid json")

    assert release_info_module.release_labels() == {
        "version": None,
        "built_at": None,
    }


def test_non_object_metadata_degrades_to_nulls(tmp_path, monkeypatch):
    write_metadata(tmp_path, monkeypatch, ["a", "list"])

    assert release_info_module.release_labels() == {
        "version": None,
        "built_at": None,
    }


def test_non_string_fields_are_dropped(tmp_path, monkeypatch):
    """A hand-edited metadata file must not put structured values into a
    JSON response."""
    write_metadata(
        tmp_path,
        monkeypatch,
        {"git_describe": ["list"], "built_at": 1234567890},
    )

    assert release_info_module.release_labels() == {
        "version": None,
        "built_at": None,
    }


def test_version_endpoint_reports_labels_alongside_the_release(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SHIPIT_RELEASE", "b" * 40)
    monkeypatch.setenv("ENVIRONMENT", "production")
    write_metadata(
        tmp_path,
        monkeypatch,
        {
            "git_sha": "b" * 40,
            "git_describe": "v2026.08.07-2",
            "built_at": "2026-08-07T12:00:00+00:00",
        },
    )

    response = client.get("/version")

    assert response.status_code == 200
    assert response.json() == {
        "release": "b" * 40,
        "environment": "production",
        "version": "v2026.08.07-2",
        "built_at": "2026-08-07T12:00:00+00:00",
    }


def test_labels_never_override_release_or_environment(tmp_path, monkeypatch):
    """The `release`/`environment` pair is shared with every log record. A
    metadata file must not be able to shadow it, however it is spelled."""
    monkeypatch.setenv("SHIPIT_RELEASE", "c" * 40)
    monkeypatch.setenv("ENVIRONMENT", "production")
    write_metadata(
        tmp_path,
        monkeypatch,
        {
            "git_describe": "v1",
            "built_at": "2026-08-07T12:00:00+00:00",
            "release": "spoofed",
            "environment": "spoofed",
        },
    )

    body = client.get("/version").json()

    assert body["release"] == "c" * 40
    assert body["environment"] == "production"


def test_version_endpoint_leaks_no_extra_metadata(tmp_path, monkeypatch):
    """Only the descriptive labels are exposed. Local filesystem paths and the
    migration manifest stay on the box."""
    write_metadata(
        tmp_path,
        monkeypatch,
        {
            "git_sha": "c" * 40,
            "git_describe": "v1",
            "built_at": "2026-08-07T12:00:00+00:00",
            "source_repository": "/srv/shipit/repo",
            "python": "/usr/bin/python3.12",
            "migration_manifest": [{"filename": "001.sql", "checksum": "x"}],
        },
    )

    body = client.get("/version").json()

    assert set(body) == {"release", "environment", "version", "built_at"}
