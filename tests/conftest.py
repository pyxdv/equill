"""Keep the test suite offline: the default scanner config fetches opengrep-rules.

Tests that exercise ``equill.rules.fetch`` pass their own ``download`` and
``use_git=False``; anything else that would reach the network fails loudly.
"""

from __future__ import annotations

import pytest

import equill.rules


@pytest.fixture(autouse=True)
def _offline_rules(monkeypatch, tmp_path_factory):
    monkeypatch.setenv("EQUILL_CACHE", str(tmp_path_factory.mktemp("equill-cache")))

    def _blocked(*_args, **_kwargs):
        raise AssertionError("tests must not fetch opengrep-rules from the network")

    monkeypatch.setattr(equill.rules, "_git_checkout", _blocked)
    monkeypatch.setattr(equill.rules, "_download", _blocked)
