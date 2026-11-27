"""End-to-end tests: unfit's whole flow against a fake wine binary."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
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

PACK_NAME = "Example Game [FitGirl Repack]"


@pytest.fixture
def pack(make_pack: Callable[[str, Sequence[str]], Path]) -> Path:
    """A one-volume pack."""
    return make_pack(PACK_NAME, ["fg-01.bin"])


@pytest.fixture
def tool_args(make_wine: Callable[[str], Path], extractor_stub: Path) -> list[str]:
    """CLI flags that point unfit at the fake wine and extractor."""
    return ["--wine", str(make_wine(FAKE_WINE)), "--extractor", str(extractor_stub)]


def test_extracts_into_a_destination_that_does_not_exist(
    sandbox: Path, pack: Path, tool_args: list[str]
) -> None:
    dest = sandbox / "fresh" / "Example Game"

    code = unfit.main([str(pack), "-d", str(dest), *tool_args, "--no-progress"])

    assert code == 0
    assert (dest / "payload.bin").read_bytes() == b"game data"
    assert list((sandbox / "state/logs").glob("*-Example Game.log"))


def test_quiet_hides_extractor_output(
    sandbox: Path,
    pack: Path,
    tool_args: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    dest = sandbox / "fresh" / "Example Game"

    code = unfit.main(
        [str(pack), "-d", str(dest), *tool_args, "--no-progress", "--quiet"]
    )
    captured = capsys.readouterr()

    assert code == 0
    assert "1 files, 1 MB unpacked" not in captured.out
    assert "bins: 1 ok" in captured.out


def test_dry_run_allows_a_non_empty_destination(
    sandbox: Path,
    pack: Path,
    tool_args: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    dest = sandbox / "occupied"
    dest.mkdir()
    (dest / "keep.txt").write_text("keep")

    code = unfit.main([str(pack), "-d", str(dest), *tool_args, "--dry-run"])
    captured = capsys.readouterr()

    assert code == 0
    assert "would run:" in captured.out
    assert "needs --overwrite" in captured.out
    assert (dest / "keep.txt").read_text() == "keep"


def test_rejects_a_destination_inside_the_pack(
    pack: Path, tool_args: list[str]
) -> None:
    code = unfit.main(
        [str(pack), "-d", str(pack / "output"), *tool_args, "--no-progress"]
    )

    assert code == 2
    assert not (pack / "output").exists()
