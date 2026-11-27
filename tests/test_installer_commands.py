"""Tests for replaying helper commands that the install script runs itself."""

from __future__ import annotations

import hashlib
import lzma
import os
import shutil
import struct
import zlib
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

import unfit

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="the fake wine binary is a POSIX script"
)

# Stand-in for wine: x5.exe behaves like hpatchz (NEW = OLD + DIFF, refusing
# to overwrite NEW), x2n.exe appends DATA and MAP to TARGET in place, and
# winepath maps Linux paths to drive Z:.
FAKE_WINE = r"""#!/usr/bin/env python3
import sys
from pathlib import Path

def unix(path):
    return Path(path[2:].replace("\\", "/"))

args = sys.argv[1:]
if args == ["--version"]:
    print("wine-11.0 (fake)")
    raise SystemExit(0)
tool = args[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
operands = [unix(arg) for arg in args[1:] if not arg.startswith("-")]
if tool == "winepath.exe":
    print("Z:" + args[2].replace("/", "\\"))
elif tool == "x5.exe":
    old, diff, new = operands
    if diff.read_bytes() == b"BAD":
        print("WARNING: radv is not a conformant Vulkan implementation, testing")
        print("0024:fixme:winediag:loader_init wine-staging is a testing version")
        print("is hdiff file? getCompressedDiffInfo() ERROR!")
        print("")
        print("hpatchz time: 0.000 s")
        raise SystemExit(9)
    if new.exists():
        print("out file already exists")
        raise SystemExit(1)
    new.write_bytes(old.read_bytes() + diff.read_bytes())
elif tool == "x2n.exe":
    target, data, index = operands
    with target.open("ab") as handle:
        handle.write(data.read_bytes() + index.read_bytes())
else:
    raise SystemExit(f"unexpected tool {tool}")
"""

# Stand-in for innoextract: writes a stub for every --include into --output-dir.
FAKE_INNOEXTRACT = r"""#!/usr/bin/env python3
import sys
from pathlib import Path

args = sys.argv[1:]
output = Path(args[args.index("--output-dir") + 1])
for position, argument in enumerate(args):
    if argument == "--include":
        target = output / args[position + 1]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"stub")
"""

PAKS = "{app}\\Game\\Paks\\"
SCRIPT = [
    "Preparing installation...",
    "{tmp}\\",
    "/C ",
    "{tmp}\\fnr.exe",
    " arc.ini fgrplc -1",
    "{cmd}",
    PAKS,
    "{src}\\fg-02.bin",
    PAKS,
    "/C ",
    "{tmp}\\x5.exe",
    " -s-2g 1.fgpack Game.pak.x5 Game.pak&&del 1.fgpack Game.pak.x5",
    "{cmd}",
    PAKS,
    "/C ",
    "{tmp}\\x5.exe",
    " -s-2g 2.fgpack Game.pak.x2d_a.x5 Game.pak.x2d_a&&del 2.fgpack Game.pak.x2d_a.x5",
    "{cmd}",
    PAKS,
    "/C ",
    "{tmp}\\x2n.exe",
    " Game.pak Game.pak.x2d_a Game.pak.x2m_a&&del Game.pak.x2d_a&&del Game.pak.x2m_a",
    "{cmd}",
]
PIECES = {
    "1.fgpack": b"OLD1",
    "Game.pak.x5": b"DIFF1",
    "2.fgpack": b"OLD2",
    "Game.pak.x2d_a.x5": b"DIFF2",
    "Game.pak.x2m_a": b"MAP",
}
FULL_PAK = b"OLD1DIFF1OLD2DIFF2MAP"
LOADER_MAGIC = b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a"
STRING_TYPE = 0x11
FILLER = b"\x03\x00\x16\x00\x00\x60\x05\x28\x00\x00\x00\x04\x04"


def compiled_script(literals: Sequence[str]) -> bytes:
    """Encode literals the way PascalScript stores constants, between opcodes."""
    parts = [b"IFPS\x17\x00\x00\x00"]
    for literal in literals:
        body = literal.encode("cp1252")
        parts.append(FILLER + struct.pack("<BII", 1, STRING_TYPE, len(body)) + body)
    return b"".join(parts) + FILLER


def setup_exe(literals: Sequence[str]) -> bytes:
    """Build a minimal Inno Setup 5.5 installer whose header holds ``literals``."""
    header = b"setup header fields" + compiled_script(literals)
    lzma_filter = {"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2}
    lzma_filter["dict_size"] = 1 << 16
    compressed = lzma.compress(header, lzma.FORMAT_RAW, filters=[lzma_filter])
    payload = bytes([93]) + struct.pack("<I", 1 << 16) + compressed
    block = b"".join(
        struct.pack("<I", zlib.crc32(payload[offset : offset + 4096]))
        + payload[offset : offset + 4096]
        for offset in range(0, len(payload), 4096)
    )
    sizes = struct.pack("<IB", len(block), 1)
    setup_data = (
        b"Inno Setup Setup Data (5.5.0) (u)".ljust(64, b"\0")
        + struct.pack("<I", zlib.crc32(sizes))
        + sizes
        + block
    )
    stub = b"MZ" + bytes(254)
    offset0 = len(stub) + len(LOADER_MAGIC) + 32
    fields = struct.pack("<7I", 1, 0, 0, 0, 0, offset0, 0)
    table = LOADER_MAGIC + fields
    table += struct.pack("<I", zlib.crc32(table))
    return stub + table + setup_data


def md5(data: bytes) -> str:
    """Return the MD5 hex digest of ``data``."""
    return hashlib.md5(data).hexdigest()


def write(path: Path, data: bytes) -> Path:
    """Write bytes, creating parent folders."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def make_pack(root: Path, literals: Sequence[str] = SCRIPT) -> Path:
    """A pack folder that only holds the installer."""
    pack = root / "pack"
    write(pack / "setup.exe", setup_exe(literals))
    return pack


def make_unpacked(root: Path) -> Path:
    """An unpacked folder as fitgirl-extractor leaves it: pieces in the root."""
    dest = root / "game"
    for name, content in PIECES.items():
        write(dest / name, content)
    write(dest / "Game/Paks/other.ucas", b"other")
    manifest = (
        f"{md5(FULL_PAK)} *..\\Game\\Paks\\Game.pak\r\n"
        f"{md5(b'other')} *..\\Game\\Paks\\other.ucas\r\n"
    )
    write(dest / "_Redist/fitgirl.md5", manifest.encode())
    return dest


@pytest.fixture
def fake_innoextract(sandbox: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake innoextract that ``shutil.which`` finds; no other tool is on PATH."""
    tool = write(sandbox / "bin/innoextract", FAKE_INNOEXTRACT.encode())
    tool.chmod(0o755)
    monkeypatch.setattr(
        shutil, "which", lambda name: str(tool) if name == "innoextract" else None
    )
    return tool


@pytest.fixture
def fake_wine(make_wine: Callable[[str], Path], fake_innoextract: Path) -> Path:
    """A fake wine binary, with the fake innoextract installed."""
    return make_wine(FAKE_WINE)


def finish(pack: Path | None, dest: Path, wine: Path, *extra: str) -> int:
    """Run ``unfit --finish [PACK -d] DEST``."""
    target = [str(pack), "-d", str(dest)] if pack else [str(dest)]
    return unfit.main(
        ["--finish", *target, "--wine", str(wine), "--no-progress", *extra]
    )


def test_header_literals_round_trip(tmp_path: Path) -> None:
    setup = write(tmp_path / "setup.exe", setup_exe(SCRIPT))

    literals = unfit.installer_literals(unfit.read_setup_header(setup))

    assert literals == SCRIPT


def test_parse_finds_the_commands_in_order() -> None:
    commands, others = unfit.parse_installer_commands(SCRIPT)

    assert [command.workdir for command in commands] == ["Game\\Paks"] * 3
    assert [command.chain.steps[0].tool for command in commands] == [
        "x5.exe",
        "x5.exe",
        "x2n.exe",
    ]
    assert commands[2].chain.steps[1:] == (
        unfit.Step("del", ("Game.pak.x2d_a",)),
        unfit.Step("del", ("Game.pak.x2m_a",)),
    )
    assert others == [], "tools that only touch {tmp} files are not reported"


def test_parse_reports_unknown_tools_in_the_game_folder() -> None:
    literals = [PAKS, "/C ", "{tmp}\\mystery.exe", " a.bin b.bin", "{cmd}"]

    commands, others = unfit.parse_installer_commands(literals)

    assert commands == []
    assert others == ["mystery.exe"]


def test_finish_with_the_pack_rebuilds_the_archive(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack, dest = make_pack(tmp_path), make_unpacked(tmp_path)

    code = finish(pack, dest, fake_wine)
    output = capsys.readouterr().out

    assert code == 0, output
    paks = dest / "Game/Paks"
    assert (paks / "Game.pak").read_bytes() == FULL_PAK
    assert sorted(path.name for path in paks.iterdir()) == ["Game.pak", "other.ucas"]
    assert not any((dest / name).exists() for name in PIECES)
    assert not (dest / unfit.TOOL_STAGING_DIR).exists()
    assert not (dest / unfit.TRASH_DIR).exists()
    assert "replaying 3 command(s) from setup.exe" in output
    assert "3 command chain(s) ran" in output
    assert "2 ok, 0 bad, 0 missing" in output


def test_finish_twice_needs_no_tools(
    tmp_path: Path,
    fake_wine: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pack, dest = make_pack(tmp_path), make_unpacked(tmp_path)
    assert finish(pack, dest, fake_wine) == 0
    capsys.readouterr()
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    code = finish(pack, dest, fake_wine)
    output = capsys.readouterr().out

    assert code == 0, output
    assert "0 command chain(s) ran, 3 skipped" in output
    assert "2 ok, 0 bad, 0 missing" in output


def test_a_missing_optional_volume_skips_its_commands(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack, dest = make_pack(tmp_path), make_unpacked(tmp_path)
    (dest / "Game.pak.x2d_a.x5").unlink()
    (dest / "Game.pak.x2m_a").unlink()

    code = finish(pack, dest, fake_wine, "--skip-verify")
    captured = capsys.readouterr()

    assert code == 0, captured.err
    assert (dest / "Game/Paks/Game.pak").read_bytes() == b"OLD1DIFF1"
    assert "1 command chain(s) ran, 2 skipped" in captured.out
    assert "setup.exe command 2: skipped" in captured.err
    assert "left 2.fgpack in place" in captured.err
    assert (dest / "2.fgpack").is_file()


def test_an_interrupted_output_is_replaced(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack, dest = make_pack(tmp_path), make_unpacked(tmp_path)
    write(dest / "Game/Paks/Game.pak", b"partial")

    code = finish(pack, dest, fake_wine)

    assert code == 0, capsys.readouterr().err
    assert (dest / "Game/Paks/Game.pak").read_bytes() == FULL_PAK


def test_a_failing_helper_reports_its_own_error(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack, dest = make_pack(tmp_path), make_unpacked(tmp_path)
    write(dest / "Game.pak.x5", b"BAD")

    code = finish(pack, dest, fake_wine)
    errors = capsys.readouterr().err

    assert code == 1
    assert (
        "setup.exe command 1: x5.exe exited with 9: "
        "is hdiff file? getCompressedDiffInfo() ERROR! | hpatchz time: 0.000 s"
    ) in errors
    assert "radv" not in errors
    assert (dest / "Game/Paks/1.fgpack").is_file()
    assert not (dest / "Game/Paks/Game.pak").exists()
    assert not (dest / unfit.TOOL_STAGING_DIR).exists()


def test_missing_innoextract_is_reported_before_anything_moves(
    tmp_path: Path,
    make_wine: Callable[[str], Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pack, dest = make_pack(tmp_path), make_unpacked(tmp_path)
    wine = make_wine(FAKE_WINE)
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    code = finish(pack, dest, wine)
    errors = capsys.readouterr().err

    assert code == 2
    assert "innoextract is missing" in errors
    assert f"unfit --finish {pack} -d {dest}" in errors
    assert all((dest / name).is_file() for name in PIECES)


@pytest.mark.parametrize(
    "arguments",
    [
        " -s-2g 1.fgpack Game.pak.x5 ..\\..\\Game.pak",
        " -s-2g 1.fgpack Game.pak.x5 {app}\\Game.pak",
        " -s-2g 1.fgpack Game.pak.x5 Game.pak&&copy Game.pak elsewhere.pak",
        " -s-2g -z 1.fgpack Game.pak.x5 Game.pak",
        " 1.fgpack Game.pak",
    ],
)
def test_unsupported_commands_leave_the_folder_untouched(
    tmp_path: Path,
    fake_wine: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: str,
) -> None:
    script = [PAKS, "/C ", "{tmp}\\x5.exe", arguments, "{cmd}"]
    pack, dest = make_pack(tmp_path, script), make_unpacked(tmp_path)

    code = finish(pack, dest, fake_wine)
    errors = capsys.readouterr().err

    assert code == 1
    assert "post-install: not replayed" in errors
    assert all((dest / name).is_file() for name in PIECES)


def test_a_command_outside_the_game_folder_is_rejected(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    script = ["{tmp}\\", "/C ", "{tmp}\\x5.exe", " a b c", "{cmd}"]
    pack, dest = make_pack(tmp_path, script), make_unpacked(tmp_path)

    code = finish(pack, dest, fake_wine)

    assert code == 1
    assert "runs outside the game folder" in capsys.readouterr().err


def test_finish_without_the_pack_points_at_it(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = make_unpacked(tmp_path)

    code = finish(None, dest, fake_wine)
    output = capsys.readouterr().out

    assert code == 1
    assert "1 missing" in output
    assert "unfit --finish PACK_DIR -d DIR" in output


def test_an_unreadable_installer_only_warns(
    tmp_path: Path, fake_wine: Path, caplog: pytest.LogCaptureFixture
) -> None:
    setup = write(tmp_path / "pack/setup.exe", b"stub")
    dest = make_unpacked(tmp_path)

    code = unfit.run_post_install(dest, fake_wine, setup=setup)

    assert code == 0
    assert "install script commands not checked" in caplog.text


def test_a_damaged_header_chunk_is_detected(tmp_path: Path) -> None:
    data = bytearray(setup_exe(SCRIPT))
    data[-3] ^= 0xFF
    setup = write(tmp_path / "setup.exe", bytes(data))

    with pytest.raises(unfit.UnfitError, match="fails its checksum"):
        unfit.read_setup_header(setup)


def test_hpatch_operands_skip_memory_options() -> None:
    assert unfit.hpatch_operands(["-s-2g", "-m", "old", "diff", "new"]) == (
        "old",
        "diff",
        "new",
    )
