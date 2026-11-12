"""End-to-end tests: unfit's whole flow against a fake wine binary."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import unfit

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="the fake wine binary is a POSIX script"
)

FAKE_WINE = r'''#!/usr/bin/env python3
"""Stand-in for wine: answers --version, lists, and writes a small payload."""

import hashlib
import sys
from pathlib import Path

args = sys.argv[1:]
if args == ["--version"]:
    print("wine-11.0 (fake)")
    raise SystemExit(0)

if "--list" in args:
    print("    1 files, 1 MB unpacked, 1 MB packed")
    raise SystemExit(0)

destination = Path(args[args.index("-d") + 1])
destination.mkdir(parents=True, exist_ok=True)
payload = destination / "payload.bin"
payload.write_bytes(b"game data")
digest = hashlib.md5(payload.read_bytes()).hexdigest()
redist = destination / "_Redist"
redist.mkdir(exist_ok=True)
(redist / "fitgirl.md5").write_text(f"{digest} *..\\payload.bin\n")
'''


def build_pack(root: Path) -> Path:
    """Create a minimal folder that ``find_pack_files`` accepts."""
    pack = root / "Example Game [FitGirl Repack]"
    (pack / "MD5").mkdir(parents=True)
    (pack / "setup.exe").write_bytes(b"stub")
    volume = pack / "fg-01.bin"
    volume.write_bytes(b"volume")
    digest = hashlib.md5(volume.read_bytes()).hexdigest()
    (pack / "MD5/fitgirl-bins.md5").write_text(f"{digest} *..\\fg-01.bin\n")
    return pack


def build_tools(root: Path) -> tuple[Path, Path]:
    """Create the fake wine binary and a stub extractor path."""
    wine = root / "fakewine"
    wine.write_text(FAKE_WINE)
    wine.chmod(0o755)
    extractor = root / "fitgirl-extractor.exe"
    extractor.write_bytes(b"stub")
    return wine, extractor


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Send unfit's data, prefix and log directories into the test folder."""
    monkeypatch.setattr(unfit, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(unfit, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(unfit, "PREFIX_DIR", tmp_path / "data/wineprefix")
    return tmp_path


def tool_args(wine: Path, extractor: Path) -> list[str]:
    """Return the CLI flags that point unfit at the fakes."""
    return ["--wine", str(wine), "--extractor", str(extractor)]


def test_extracts_into_a_destination_that_does_not_exist(sandbox: Path) -> None:
    pack = build_pack(sandbox)
    wine, extractor = build_tools(sandbox)
    dest = sandbox / "fresh" / "Example Game"

    code = unfit.main(
        [str(pack), "-d", str(dest), *tool_args(wine, extractor), "--no-progress"]
    )

    assert code == 0
    assert (dest / "payload.bin").read_bytes() == b"game data"
    assert list((sandbox / "state/logs").glob("*-Example Game.log"))


def test_quiet_hides_extractor_output(
    sandbox: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack = build_pack(sandbox)
    wine, extractor = build_tools(sandbox)
    dest = sandbox / "fresh" / "Example Game"

    code = unfit.main(
        [
            str(pack),
            "-d",
            str(dest),
            *tool_args(wine, extractor),
            "--no-progress",
            "--quiet",
        ]
    )
    captured = capsys.readouterr()

    assert code == 0
    assert "1 files, 1 MB unpacked" not in captured.out
    assert "bins: 1 ok" in captured.out


def test_dry_run_allows_a_non_empty_destination(
    sandbox: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack = build_pack(sandbox)
    wine, extractor = build_tools(sandbox)
    dest = sandbox / "occupied"
    dest.mkdir()
    (dest / "keep.txt").write_text("keep")

    code = unfit.main(
        [str(pack), "-d", str(dest), *tool_args(wine, extractor), "--dry-run"]
    )
    captured = capsys.readouterr()

    assert code == 0
    assert "would run:" in captured.out
    assert "needs --overwrite" in captured.out
    assert (dest / "keep.txt").read_text() == "keep"


def test_rejects_a_destination_inside_the_pack(sandbox: Path) -> None:
    pack = build_pack(sandbox)
    wine, extractor = build_tools(sandbox)

    code = unfit.main(
        [
            str(pack),
            "-d",
            str(pack / "output"),
            *tool_args(wine, extractor),
            "--no-progress",
        ]
    )

    assert code == 2
    assert not (pack / "output").exists()
