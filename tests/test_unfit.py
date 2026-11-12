"""Tests for unfit's pure helpers and file-layout logic."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import unfit


def make_file(path: Path, content: bytes) -> Path:
    """Create a file with content and return its path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def test_parse_md5_manifest_handles_fitgirl_format() -> None:
    text = (
        "; comment line\n"
        "38165e76682f7405e2fde0de2a1dcf3f *..\\fg-01.bin\n"
        "\n"
        "825c2c891baec1c3a2e039e204bbd491 *..\\fg-02.bin\n"
    )
    entries = unfit.parse_md5_manifest(text)
    assert entries == {
        "fg-01.bin": "38165e76682f7405e2fde0de2a1dcf3f",
        "fg-02.bin": "825c2c891baec1c3a2e039e204bbd491",
    }


def test_parse_md5_manifest_skips_malformed_lines() -> None:
    text = (
        "not-a-hash *..\\fg-01.bin\n"
        "0123456789abcdef0123456789abcdef *..\\games\\x.nup\n"
    )
    assert unfit.parse_md5_manifest(text) == {
        "games/x.nup": "0123456789abcdef0123456789abcdef"
    }


def test_parse_md5_manifest_drops_paths_outside_the_root() -> None:
    digest = "0123456789abcdef0123456789abcdef"
    text = (
        f"{digest} *..\\games/../../escape.nup\n"
        f"{digest} *..\\/absolute.nup\n"
        f"{digest} *..\\games/kept.nup\n"
    )
    assert unfit.parse_md5_manifest(text) == {"games/kept.nup": digest}


def test_parse_md5_manifest_normalizes_repeated_parent_prefix() -> None:
    digest = "0123456789abcdef0123456789abcdef"
    entries = unfit.parse_md5_manifest(f"{digest} *..\\..\\games\\x.nup\n")
    assert entries == {"games/x.nup": digest}


def test_derive_dest_name_strips_bracket_tag(tmp_path: Path) -> None:
    pack = tmp_path / "Example Game [FitGirl Repack]"
    assert unfit.derive_dest_name(pack) == "Example Game"


def test_derive_dest_name_keeps_plain_name(tmp_path: Path) -> None:
    assert unfit.derive_dest_name(tmp_path / "Some Game") == "Some Game"


@pytest.mark.parametrize(
    ("listing", "expected"),
    [
        ("    1 files, 24435 MB unpacked, 17432 MB packed\n", 24435 * 1024 * 1024),
        (
            "    1 files, 10 MB unpacked, 5 MB packed\n"
            "    3 files, 2 MB unpacked, 1 MB packed\n",
            12 * 1024 * 1024,
        ),
        ("nothing here\n", 0),
    ],
)
def test_parse_unpacked_bytes(listing: str, expected: int) -> None:
    assert unfit.parse_unpacked_bytes(listing) == expected


def test_is_selective() -> None:
    assert unfit.is_selective("fg-selective-music.bin")
    assert not unfit.is_selective("fg-01.bin")


def test_hash_file_matches_hashlib(tmp_path: Path) -> None:
    payload = b"unfit test payload" * 1000
    target = make_file(tmp_path / "blob.bin", payload)
    assert unfit.hash_file(target) == hashlib.md5(payload).hexdigest()


def test_verify_against_manifest_classifies_files(tmp_path: Path) -> None:
    make_file(tmp_path / "good.bin", b"good")
    make_file(tmp_path / "bad.bin", b"bad")
    manifest = {
        "good.bin": hashlib.md5(b"good").hexdigest(),
        "bad.bin": "0" * 32,
        "absent.bin": "1" * 32,
    }
    report = unfit.verify_against_manifest(tmp_path, manifest)
    assert report.ok == ["good.bin"]
    assert [entry.path for entry in report.bad] == ["bad.bin"]
    assert report.missing == ["absent.bin"]
    assert not report.clean


def test_plan_root_fixups_moves_only_matching_files(tmp_path: Path) -> None:
    payload = b"game data"
    digest = hashlib.md5(payload).hexdigest()
    make_file(tmp_path / "0400.nup", payload)
    manifest = {"games/0400.nup": digest, "games/other.nup": "2" * 32}

    moves = unfit.plan_root_fixups(tmp_path, manifest)

    assert moves == [
        unfit.Move(source=tmp_path / "0400.nup", target=tmp_path / "games/0400.nup")
    ]


def test_plan_root_fixups_ignores_wrong_content(tmp_path: Path) -> None:
    make_file(tmp_path / "0400.nup", b"truncated")
    manifest = {"games/0400.nup": hashlib.md5(b"game data").hexdigest()}
    assert unfit.plan_root_fixups(tmp_path, manifest) == []


def test_apply_moves_creates_parents(tmp_path: Path) -> None:
    source = make_file(tmp_path / "a.nup", b"x")
    target = tmp_path / "games/sub/a.nup"
    unfit.apply_moves([unfit.Move(source=source, target=target)])
    assert target.read_bytes() == b"x"
    assert not source.exists()


def test_build_extract_command_extraction() -> None:
    command = unfit.build_extract_command(
        Path("/wine"),
        Path("/exe"),
        Path("/pack"),
        Path("/dest"),
        skip_bin_check=True,
        skip_verify=True,
    )
    assert command == [
        "/wine",
        "/exe",
        "/pack",
        "-d",
        "/dest",
        "--skip-bin-check",
        "--skip-verify",
    ]


def test_build_extract_command_listing_has_no_dest() -> None:
    command = unfit.build_extract_command(
        Path("/wine"), Path("/exe"), Path("/pack"), Path("/dest"), list_only=True
    )
    assert command == ["/wine", "/exe", "/pack", "--list"]


def test_pick_wine_skips_non_executable(tmp_path: Path) -> None:
    plain = make_file(tmp_path / "wine", b"#!/bin/sh\n")
    executable = make_file(tmp_path / "wine2", b"#!/bin/sh\n")
    executable.chmod(0o755)
    assert unfit.pick_wine([plain, executable]) == executable
    assert unfit.pick_wine([plain]) is None


def test_directory_size_excludes_fgtmp(tmp_path: Path) -> None:
    make_file(tmp_path / "game.bin", b"x" * 10)
    make_file(tmp_path / ".fgtmp/tmp/scratch.bin", b"y" * 100)
    assert unfit.directory_size(tmp_path) == 10


def test_check_windows_ansi_accepts_latin1_and_rejects_arrows(tmp_path: Path) -> None:
    unfit.check_windows_ansi(tmp_path / "Example Game")
    with pytest.raises(unfit.UnfitError):
        unfit.check_windows_ansi(tmp_path / "Example \u2192 Game")


def test_confirm_overwrite(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    unfit.confirm_overwrite(dest, overwrite=False)
    make_file(dest / "existing.txt", b"x")
    with pytest.raises(unfit.UnfitError):
        unfit.confirm_overwrite(dest, overwrite=False)
    unfit.confirm_overwrite(dest, overwrite=True)


def test_find_pack_files_requires_setup_and_bins(tmp_path: Path) -> None:
    with pytest.raises(unfit.UnfitError):
        unfit.find_pack_files(tmp_path)
    make_file(tmp_path / "setup.exe", b"stub")
    with pytest.raises(unfit.UnfitError):
        unfit.find_pack_files(tmp_path)
    make_file(tmp_path / "fg-01.bin", b"stub")
    with pytest.raises(unfit.UnfitError):
        unfit.find_pack_files(tmp_path)
    make_file(tmp_path / "MD5/fitgirl-bins.md5", b"; empty\n")
    pack = unfit.find_pack_files(tmp_path)
    assert pack.pack_dir == tmp_path
    assert pack.bins == (tmp_path / "fg-01.bin",)


def test_required_missing_ignores_selective() -> None:
    report = unfit.VerifyReport(
        total=3, ok=[], bad=[], missing=["fg-selective-4k.bin", "fg-03.bin"]
    )
    assert unfit.required_missing(report) == ["fg-03.bin"]


def test_main_rejects_missing_pack(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert unfit.main([str(tmp_path / "nope")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_parse_args_defaults() -> None:
    args = unfit.parse_args(["/packs/game"])
    assert args.pack_dir == Path("/packs/game")
    assert args.dest is None
    assert not args.check


def test_sha256_file(tmp_path: Path) -> None:
    payload = b"abc"
    target = make_file(tmp_path / "x", payload)
    assert unfit.sha256_file(target) == hashlib.sha256(payload).hexdigest()


def test_describe_report_mentions_optional_volumes_only_when_absent() -> None:
    report = unfit.VerifyReport(total=2, ok=["fg-01.bin", "fg-02.bin"])
    assert (
        unfit.describe_report(report, selective_missing=True)
        == "2 ok, 0 bad, 0 missing"
    )
    report.missing = ["fg-selective-4k.bin"]
    assert "1 optional selective volume(s) ignored" in unfit.describe_report(
        report, selective_missing=True
    )
    report.missing = ["fg-03.bin"]
    assert "optional" not in unfit.describe_report(report, selective_missing=True)


def test_proton_candidates_prefers_experimental(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    common = tmp_path / ".steam/steam/steamapps/common"
    experimental = common / "Proton - Experimental/files/bin/wine"
    stable = common / "Proton 9.0/files/bin/wine"
    make_file(experimental, b"#")
    make_file(stable, b"#")
    os.utime(experimental, (1, 1))
    os.utime(stable, (2, 2))

    assert unfit.proton_candidates() == [experimental, stable]


def test_ensure_extractor_redownloads_a_tampered_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = make_file(tmp_path / "fitgirl-extractor.exe", b"tampered")
    monkeypatch.setattr(unfit, "EXTRACTOR_PATH", cache)
    monkeypatch.delenv("UNFIT_EXTRACTOR", raising=False)
    downloads: list[Path] = []
    monkeypatch.setattr(unfit, "download_extractor", downloads.append)

    assert unfit.ensure_extractor(None) == cache
    assert downloads == [cache]


def test_ensure_extractor_rejects_a_missing_explicit_path(tmp_path: Path) -> None:
    with pytest.raises(unfit.UnfitError):
        unfit.ensure_extractor(tmp_path / "missing.exe")


def test_check_destination_rejects_the_pack_and_its_children(tmp_path: Path) -> None:
    pack = tmp_path / "pack"
    pack.mkdir()
    with pytest.raises(unfit.UnfitError):
        unfit.check_destination(pack, pack, overwrite=True)
    with pytest.raises(unfit.UnfitError):
        unfit.check_destination(pack, pack / "output", overwrite=True)
    unfit.check_destination(pack, tmp_path / "elsewhere", overwrite=False)
