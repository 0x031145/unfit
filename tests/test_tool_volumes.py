"""Tests for packs that ship an external decompressor in a volume of its own."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import unfit

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="the fake wine binary is a POSIX script"
)

# Stand-in for wine + fitgirl-extractor, shaped like a repack
# whose fg-02.bin holds tools\xtool.exe, and fg-01.bin can only be unpacked
# when that tool sits next to the running extractor. arc.ini appears in the
# work folder while the extractor runs and is deleted when it exits.
FAKE_WINE = r"""#!/usr/bin/env python3
import hashlib
import shutil
import sys
import time
from pathlib import Path

args = sys.argv[1:]
if args == ["--version"]:
    print("wine-11.0 (fake)")
    raise SystemExit(0)
extractor = Path(args[0])
if "--list" in args:
    print("    1 files, 1 MB unpacked, 1 MB packed")
    raise SystemExit(0)
dest = Path(args[args.index("-d") + 1])
only = [args[i + 1] for i, arg in enumerate(args) if arg == "--only"]
volumes = only or ["fg-01.bin", "fg-02.bin"]

work = dest / ".fgtmp/setup/tmp"
work.mkdir(parents=True, exist_ok=True)
(work / "arc.ini").write_text(
    "[External compressor:example]\r\n"
    "header    = 0\r\n"
    "unpackcmd = tools\\xtool.exe decode -t100p - - <stdin> <stdout>\r\n"
)
time.sleep(1.0)

code = 0
for volume in volumes:
    print(f"==> Unpacking {volume}")
    if volume == "fg-02.bin":
        (dest / "tools").mkdir(exist_ok=True)
        (dest / "tools/xtool.exe").write_bytes(b"tool")
        print(f"==> {volume}: 1 files in 0 s")
    elif (extractor.parent / "tools/xtool.exe").is_file():
        (dest / "game.pak").write_bytes(b"game data")
        print(f"==> {volume}: 1 files in 0 s")
    else:
        (dest / "game.pak").write_bytes(b"half")
        print("    ERROR: archive data corrupted (decompression fails)")
        print(f"WARNING: {volume} failed (result -1): archive data corrupted")
        code = 1

redist = dest / "_Redist"
redist.mkdir(exist_ok=True)
digest = hashlib.md5(b"game data").hexdigest()
(redist / "fitgirl.md5").write_text(f"{digest} *..\\game.pak\n")
shutil.rmtree(dest / ".fgtmp")
raise SystemExit(code)
"""


def build_pack(root: Path) -> Path:
    """Create a two-volume pack folder that ``find_pack_files`` accepts."""
    pack = root / "Tool Game [FitGirl Repack]"
    (pack / "MD5").mkdir(parents=True)
    (pack / "setup.exe").write_bytes(b"stub")
    lines = []
    for name in ("fg-01.bin", "fg-02.bin"):
        (pack / name).write_bytes(name.encode())
        lines.append(f"{hashlib.md5(name.encode()).hexdigest()} *..\\{name}")
    (pack / "MD5/fitgirl-bins.md5").write_text("\n".join(lines) + "\n")
    return pack


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Send unfit's data, prefix and log directories into the test folder."""
    monkeypatch.setattr(unfit, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(unfit, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(unfit, "PREFIX_DIR", tmp_path / "data/wineprefix")
    return tmp_path


def run_unfit(sandbox: Path, dest: Path) -> int:
    """Run unfit on the fake pack with the fake wine and extractor."""
    wine = sandbox / "fakewine"
    wine.write_text(FAKE_WINE)
    wine.chmod(0o755)
    extractor = sandbox / "bin/fitgirl-extractor.exe"
    extractor.parent.mkdir()
    extractor.write_bytes(b"stub")
    pack = build_pack(sandbox)
    return unfit.main(
        [
            str(pack),
            "-d",
            str(dest),
            "--wine",
            str(wine),
            "--extractor",
            str(extractor),
            "--no-progress",
        ]
    )


def test_failed_volume_is_retried_with_the_tools_next_to_the_extractor(
    sandbox: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = sandbox / "game"

    code = run_unfit(sandbox, dest)
    output = capsys.readouterr().out

    assert code == 0, output
    assert "retrying fg-01.bin with the installer tools tools\\" in output
    assert (dest / "game.pak").read_bytes() == b"game data"
    assert not (dest / "tools").exists(), "installer tools leave the game folder"
    assert not (dest / unfit.TOOL_STAGING_DIR).exists()
    assert "removed installer tools tools\\" in output
    assert "1 ok, 0 bad, 0 missing" in output


def test_parse_arc_tool_dirs_keeps_relative_folders_only() -> None:
    text = (
        "[External compressor:xt]\r\n"
        "unpackcmd = xtool.exe decode - - <stdin> <stdout>\r\n"
        "[External compressor:alpha]\r\n"
        "unpackcmd = tools\\xtool.exe decode -t100p - - <stdin> <stdout>\r\n"
        "[External compressor:beta]\r\n"
        "UnpackCmd=helpers\\xtool.exe decode\r\n"
        '[External compressor:q]\r\nunpackcmd = "q dir\\q.exe" x\r\n'
        "[External compressor:abs]\r\nunpackcmd = C:\\tools\\a.exe x\r\n"
        "[External compressor:up]\r\nunpackcmd = ..\\up\\a.exe x\r\n"
        "[External compressor:pack]\r\npackcmd = packer\\p.exe a\r\n"
    )
    assert unfit.parse_arc_tool_dirs(text) == {"tools", "helpers", "q dir"}


def test_find_tool_dirs_skips_folders_the_manifest_owns(tmp_path: Path) -> None:
    (tmp_path / "helpers").mkdir()
    (tmp_path / "TOOLS").mkdir()
    (tmp_path / "bin").mkdir()
    (tmp_path / "other").mkdir()
    (tmp_path / "_Redist").mkdir()
    digest = "0" * 32
    (tmp_path / "_Redist/fitgirl.md5").write_text(f"{digest} *..\\bin\\game.exe\n")

    found = unfit.find_tool_dirs(tmp_path, {"tools", "helpers", "bin"})

    assert found == [tmp_path / "TOOLS", tmp_path / "helpers"]


def test_collect_failed_volume_reads_extractor_warnings() -> None:
    failed: list[str] = []
    unfit.collect_failed_volume(
        "WARNING: fg-01.bin failed (result -1): archive data corrupted\n", failed
    )
    unfit.collect_failed_volume("    ERROR: archive data corrupted\n", failed)
    unfit.collect_failed_volume("WARNING: fg-01.bin failed (result -1)\n", failed)
    assert failed == ["fg-01.bin"]


def test_build_extract_command_passes_only() -> None:
    command = unfit.build_extract_command(
        Path("/usr/bin/wine"),
        Path("/x/fitgirl-extractor.exe"),
        Path("/pack"),
        Path("/dest"),
        only=["fg-01.bin"],
    )
    assert command[-2:] == ["--only", "fg-01.bin"]
