"""Shared fixtures. Every host, address and name in the tests is synthetic."""

from __future__ import annotations

import pytest

from takestock import config
from takestock.policy import Policy


@pytest.fixture(scope="session")
def baseline() -> dict:
    """The bundled algorithm baseline, loaded once."""
    return config.load_yaml_strict(config.BUNDLED_DATA_DIR / "baseline.yaml")


@pytest.fixture()
def policy(baseline: dict) -> Policy:
    """A fresh grader over the bundled baseline."""
    return Policy(baseline)


@pytest.fixture(scope="session")
def port_table() -> dict:
    """The bundled port-encryption table, indexed."""
    import csv

    from takestock.plaintext import build_index
    with (config.BUNDLED_DATA_DIR / "port-encryption.csv").open(newline="") as f:
        return build_index(list(csv.DictReader(f)))


@pytest.fixture(autouse=True)
def _isolated_workspace(monkeypatch: pytest.MonkeyPatch):
    """No test sees the caller's workspace settings."""
    monkeypatch.delenv(config.ENV_VAR, raising=False)
    monkeypatch.delenv(config.INBOX_ENV_VAR, raising=False)
    config.set_workspace(None)
    yield
    config.set_workspace(None)
