"""Shared test hygiene: the pipeline reads and (via ``aegis.edition.apply_edition``) *writes*
``os.environ``, so every test gets the environment it started with back — including keys the
test never touched. (``monkeypatch.delenv`` on an absent key records nothing, which is how an
edition default leaked from one test into the next.)"""

import os

import pytest


@pytest.fixture(autouse=True)
def _restore_environ(tmp_path):
    snapshot = dict(os.environ)
    # the HITL approvals journal is a file; give every test its own so approvals never leak between tests
    os.environ["AEGIS_HITL_STATE"] = str(tmp_path / "hitl-pending.jsonl")
    yield
    os.environ.clear()
    os.environ.update(snapshot)
