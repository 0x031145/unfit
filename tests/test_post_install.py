"""Tests for replaying FitGirl's work\\build*.bat post-install scripts."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

import unfit

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="the fake wine binary is a POSIX script"
)

# Stand-in for wine running FitGirl's helpers: "fgpack" strips a 4-byte
# header and winepath maps Linux paths to drive Z:.
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
if tool == "winepath.exe":
    print("Z:" + args[2].replace("/", "\\"))
elif tool == "fgpack.exe":
    source, target = unix(args[1]), unix(args[2])
    target.write_bytes(source.read_bytes()[4:])
else:
    raise SystemExit(f"unexpected tool {tool}")
"""

# Stand-in for xdelta3: appends the patch to the source, and fails on a
# source named bad.vid_, after the chain already deleted bad.vid.
FAKE_XDELTA = r"""#!/usr/bin/env python3
import sys
from pathlib import Path

source, patch, output = (Path(arg) for arg in sys.argv[-3:])
if source.name == "bad.vid_":
    print("xdelta3: broken patch")
    raise SystemExit(3)
output.write_bytes(source.read_bytes() + patch.read_bytes())
"""

CHAIN = (
    'cmd /c ""fitgirl2-path\\work\\fgpack.exe" {n} {n}_&&del {n}&&'
    '"fitgirl2-path\\work\\x.exe" -f -d -s {n}_ {n}.x {n}&&del {n}_ {n}.x"'
)

PACKED = {"a.vid": b"clip-a", "B.vid": b"clip-bb"}
PATCH = b"-tail"


def md5(data: bytes) -> str:
    """Return the MD5 hex digest of ``data``."""
    return hashlib.md5(data).hexdigest()


def write(path: Path, data: bytes | str) -> Path:
    """Write bytes or CRLF text, creating parent folders."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_bytes(data.replace("\n", "\r\n").encode())
    else:
        path.write_bytes(data)
    return path


def expected_file(name: str) -> bytes:
    """The bytes a file has after fgpack and the patch."""
    return PACKED[name] + PATCH


def expected_archive() -> bytes:
    """archive.pak after raw.exe copied both files in."""
    data = bytearray(64)
    for offset, name in ((8, "a.vid"), (30, "B.vid")):
        content = expected_file(name)
        data[offset : offset + len(content)] = content
    return bytes(data)


def build_unpacked(root: Path, *, extra_build02: str = "") -> Path:
    """Create an unpacked folder shaped like a repack that rebuilds packed files."""
    dest = root / "game"
    for name, content in PACKED.items():
        write(dest / "Game/media" / name, b"PKD:" + content)
        write(dest / "Game/media" / f"{name}.x", PATCH)
    write(dest / "Game/archive.pak", bytes(64))
    write(dest / "Game/placeholder.pak", b"marker")
    work = dest / "work/work"
    write(work / "fgpack.exe", b"stub")
    write(work / "x.exe", b"stub")
    write(work / "raw.exe", b"stub")
    write(
        work / "fitgirl01.txt",
        "\n".join(CHAIN.format(n=name) for name in PACKED),
    )
    write(
        work / "build01.bat",
        '"fitgirl2-path\\work\\run.exe" " " http://example.invalid '
        '"fitgirl2-path\\work\\fitgirl01.txt" 0\n'
        'del "fitgirl2-path\\work\\fitgirl01.txt"\n'
        'del "fitgirl2-path\\work\\build01.bat"\n',
    )
    write(
        work / "build02.bat",
        ":start\n"
        '"fitgirl2-path\\work\\countdown.exe" 1\n'
        "if not exist archive.pak goto start\n\n"
        '"fitgirl2-path\\work\\raw.exe" "media\\a.vid" archive.pak -ioff=0 -ooff=8\n'
        '"fitgirl2-path\\work\\raw.exe" "media\\b.vid" archive.pak -ioff=0 -ooff=30\n'
        f"{extra_build02}"
        "echo done >>file.done\n"
        'del "fitgirl2-path\\work\\build02.bat"\n',
    )
    write(
        work / "build03.bat",
        ":start2\n"
        '"fitgirl2-path\\work\\countdown.exe" 1\n'
        "if not exist file.done goto start2\n"
        "del file.done placeholder.pak\n",
    )
    manifest = [
        f"{md5(expected_file(name))} *..\\Game\\media\\{name}" for name in PACKED
    ]
    manifest.append(f"{md5(expected_archive())} *..\\Game\\archive.pak")
    write(dest / "_Redist/fitgirl.md5", "\n".join(manifest) + "\n")
    return dest


@pytest.fixture
def fake_xdelta(sandbox: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake xdelta3 that ``shutil.which`` finds; no other tool is on PATH."""
    xdelta = sandbox / "bin/xdelta3"
    xdelta.parent.mkdir(parents=True, exist_ok=True)
    xdelta.write_text(FAKE_XDELTA)
    xdelta.chmod(0o755)
    monkeypatch.setattr(
        shutil, "which", lambda name: str(xdelta) if name == "xdelta3" else None
    )
    return xdelta


@pytest.fixture
def fake_wine(make_wine: Callable[[str], Path], fake_xdelta: Path) -> Path:
    """A fake wine binary, with the fake xdelta3 installed."""
    return make_wine(FAKE_WINE)


def finish(dest: Path, wine: Path) -> int:
    """Run ``unfit --finish`` against ``dest``."""
    return unfit.main(["--finish", str(dest), "--wine", str(wine), "--no-progress"])


def test_finish_replays_the_scripts(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = build_unpacked(tmp_path)

    code = finish(dest, fake_wine)
    output = capsys.readouterr().out

    assert code == 0, output
    media = dest / "Game/media"
    assert (media / "a.vid").read_bytes() == expected_file("a.vid")
    assert (media / "B.vid").read_bytes() == expected_file("B.vid")
    assert (dest / "Game/archive.pak").read_bytes() == expected_archive()
    assert not (dest / "Game/placeholder.pak").exists()
    assert sorted(path.name for path in media.iterdir()) == ["B.vid", "a.vid"]
    assert not (dest / unfit.TRASH_DIR).exists()
    assert (dest / "work/work/build01.bat").is_file()
    assert "5 command chain(s) ran" in output
    assert "skipped" not in output
    assert "3 ok, 0 bad, 0 missing" in output


def test_finish_twice_skips_what_already_ran(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = build_unpacked(tmp_path)
    assert finish(dest, fake_wine) == 0
    capsys.readouterr()

    code = finish(dest, fake_wine)
    output = capsys.readouterr().out

    assert code == 0, output
    assert "2 command chain(s) ran, 3 skipped" in output
    assert "3 ok, 0 bad, 0 missing" in output


@pytest.mark.parametrize(
    "line",
    [
        '"fitgirl2-path\\work\\evil.exe" archive.pak\n',
        "copy archive.pak elsewhere.pak\n",
        '"fitgirl2-path\\work\\raw.exe" "media\\a.vid" ..\\..\\out.bin\n',
        '"fitgirl2-path\\work\\raw.exe" "media\\a.vid" C:\\out.bin\n',
        '"fitgirl2-path\\work\\raw.exe" "media\\a.vid" archive.pak -zero\n',
        "del *.pak\n",
        "echo [settings] > settings.ini\n",
    ],
)
def test_unsupported_commands_leave_the_folder_untouched(
    tmp_path: Path,
    fake_wine: Path,
    capsys: pytest.CaptureFixture[str],
    line: str,
) -> None:
    dest = build_unpacked(tmp_path, extra_build02=line)

    code = finish(dest, fake_wine)
    errors = capsys.readouterr().err

    assert code == 1
    assert "post-install: not replayed" in errors
    assert (dest / "Game/media/a.vid").read_bytes() == b"PKD:clip-a"
    assert (dest / "Game/media/a.vid.x").is_file()
    assert (dest / "Game/placeholder.pak").is_file()


def test_missing_xdelta3_is_reported_before_anything_runs(
    tmp_path: Path,
    make_wine: Callable[[str], Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dest = build_unpacked(tmp_path)
    wine = make_wine(FAKE_WINE)
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    code = finish(dest, wine)
    errors = capsys.readouterr().err

    assert code == 2
    assert "xdelta3 is missing" in errors
    assert f"unfit --finish {dest}" in errors
    assert (dest / "Game/media/a.vid").read_bytes() == b"PKD:clip-a"
    assert (dest / "Game/placeholder.pak").is_file()


def test_a_failing_chain_keeps_the_files_it_deleted(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = build_unpacked(tmp_path)
    work = dest / "work/work"
    write(dest / "Game/media/bad.vid", b"PKD:broken")
    write(dest / "Game/media/bad.vid.x", PATCH)
    with (work / "fitgirl01.txt").open("ab") as handle:
        handle.write(b"\r\n" + CHAIN.format(n="bad.vid").encode())

    code = finish(dest, fake_wine)
    errors = capsys.readouterr().err

    assert code == 1
    assert "post-install: failed at" in errors
    assert "xdelta3 exited with 3: xdelta3: broken patch" in errors
    assert "deleted files kept in" in errors
    assert not (dest / "Game/media/bad.vid").exists()
    kept = list((dest / unfit.TRASH_DIR).rglob("*bad.vid"))
    assert [path.read_bytes() for path in kept] == [b"PKD:broken"]
    assert (dest / "Game/placeholder.pak").is_file(), "later scripts must not run"


def test_extraction_without_scripts_is_a_no_op(
    tmp_path: Path, fake_wine: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "plain"
    write(dest / "data.bin", b"x")

    assert unfit.run_post_install(dest, fake_wine) == 0
    assert capsys.readouterr().out == ""


def test_split_cmd_words_handles_quotes_and_empty_arguments() -> None:
    words = unfit.split_cmd_words('"fitgirl2-path\\work\\run.exe" " " "a b"c ""')
    assert words == ["fitgirl2-path\\work\\run.exe", " ", "a bc", ""]


def test_split_and_chain_ignores_ampersands_in_quotes() -> None:
    parts = unfit.split_and_chain('one "&&two" && three&&four')
    assert parts == ['one "&&two"', "three", "four"]


def test_parse_chain_text_unwraps_cmd_c() -> None:
    steps = unfit.parse_chain_text(CHAIN.format(n="m.vid"), "test:1")
    assert [step.tool for step in steps] == ["fgpack.exe", "del", "x.exe", "del"]
    assert steps[2].args == ("-f", "-d", "-s", "m.vid_", "m.vid.x", "m.vid")


def test_raw_copy_honours_offsets_and_keeps_the_rest(tmp_path: Path) -> None:
    source = write(tmp_path / "in.bin", b"0123456789")
    target = write(tmp_path / "out.bin", b"abcdefghij")

    unfit.raw_copy(source, target, {"ioff": 2, "ilen": 3, "ooff": 5})

    assert target.read_bytes() == b"abcde234ij"


def test_locate_chain_rejects_ambiguous_folders(tmp_path: Path) -> None:
    write(tmp_path / "one/clip.vid", b"x")
    write(tmp_path / "two/clip.vid", b"x")
    chain = unfit.Chain("test:1", (unfit.Step("raw.exe", ("clip.vid", "out.bin")),))

    with pytest.raises(unfit.UnfitError, match="several folders"):
        unfit.locate_chain(unfit.FileIndex(tmp_path), chain)


def test_locate_chain_matches_case_insensitively(tmp_path: Path) -> None:
    write(tmp_path / "Game/Media/Clip.VID", b"x")
    chain = unfit.Chain(
        "test:1", (unfit.Step("raw.exe", ("media\\clip.vid", "archive.pak")),)
    )

    assert unfit.locate_chain(unfit.FileIndex(tmp_path), chain) == "Game"


def test_raw_copy_rejects_a_short_source(tmp_path: Path) -> None:
    source = write(tmp_path / "in.bin", b"0123")
    target = write(tmp_path / "out.bin", b"abcdefghij")

    with pytest.raises(unfit.UnfitError, match="shorter than raw.exe expects"):
        unfit.raw_copy(source, target, {"ioff": 2, "ilen": 5, "ooff": 0})
