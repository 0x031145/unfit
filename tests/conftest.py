"""Shared fixtures: an isolated unfit state, fake packs and fake wine binaries."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

import unfit


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Send unfit's data, prefix and log directories into the test folder."""
    monkeypatch.setattr(unfit, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(unfit, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(unfit, "PREFIX_DIR", tmp_path / "data/wineprefix")
    return tmp_path


@pytest.fixture
def make_pack(sandbox: Path) -> Callable[[str, Sequence[str]], Path]:
    """Return a builder for pack folders that ``find_pack_files`` accepts."""

    def build(name: str, volumes: Sequence[str]) -> Path:
        pack = sandbox / name
        (pack / "MD5").mkdir(parents=True)
        (pack / "setup.exe").write_bytes(b"stub")
        lines = []
        for volume in volumes:
            (pack / volume).write_bytes(volume.encode())
            digest = hashlib.md5(volume.encode()).hexdigest()
            lines.append(f"{digest} *..\\{volume}")
        (pack / "MD5/fitgirl-bins.md5").write_text("\n".join(lines) + "\n")
        return pack

    return build


@pytest.fixture
def make_wine(sandbox: Path) -> Callable[[str], Path]:
    """Return an installer for a fake wine binary made from a Python script."""

    def install(script: str) -> Path:
        wine = sandbox / "fakewine"
        wine.write_text(script)
        wine.chmod(0o755)
        return wine

    return install


@pytest.fixture
def extractor_stub(sandbox: Path) -> Path:
    """A placeholder ``fitgirl-extractor.exe`` in its own folder."""
    extractor = sandbox / "bin/fitgirl-extractor.exe"
    extractor.parent.mkdir(parents=True, exist_ok=True)
    extractor.write_bytes(b"stub")
    return extractor
