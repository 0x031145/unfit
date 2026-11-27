#!/usr/bin/env python3
"""unfit - verify and unpack FitGirl repacks on Linux and macOS.

FitGirl ``.bin`` volumes are produced by FitGirl's own modified FreeArc
(``unarc.dll`` shipped inside ``setup.exe``), so stock ``unarc`` cannot read
them.  This script drives ``fitgirl-extractor.exe`` (which calls that DLL under
Wine), and adds the checks that matter on POSIX systems: hash verification of
the ``.bin`` volumes, path and disk-space validation, a persistent Wine
prefix, and a post-extraction pass that repairs files the installer would have
moved.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import functools
import hashlib
import logging
import lzma
import os
import platform
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zlib
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import NamedTuple, TextIO

UNFIT_VERSION = "0.1.0"
EXTRACTOR_VERSION = "0.2.1"
EXTRACTOR_SHA256 = "d4dbe676ee1b9eb23b9dc416ec69654da717c59aa89cb125557b11af59d98054"
EXTRACTOR_URL = (
    "https://github.com/pisek/fitgirl-extractor/releases/download/"
    f"v{EXTRACTOR_VERSION}/fitgirl-extractor.exe"
)

LOGGER = logging.getLogger("unfit")


def default_data_dir() -> Path:
    """Return the default directory for cached tools and the Wine prefix."""
    env = os.environ.get("UNFIT_DATA_DIR")
    if env:
        return Path(env).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/unfit"
    return Path.home() / ".local/share/unfit"


def default_state_dir() -> Path:
    """Return the default directory for extraction logs."""
    env = os.environ.get("UNFIT_STATE_DIR")
    if env:
        return Path(env).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library/Logs/unfit"
    return Path.home() / ".local/state/unfit"


DATA_DIR = default_data_dir()
STATE_DIR = default_state_dir()
PREFIX_DIR = DATA_DIR / "wineprefix"
EXTRACTOR_PATH = DATA_DIR / "fitgirl-extractor.exe"

CHUNK_SIZE = 8 << 20
SPACE_MARGIN = 1 << 30
PROGRESS_INTERVAL = 1.5
REDRAW_INTERVAL = 0.2
HASH_WORKERS = min(8, os.cpu_count() or 1)

SELECTIVE_PREFIX = "fg-selective"
MANIFEST_TAG = re.compile(r"\s*\[[^\]]*\]\s*$")
LIST_TOTAL = re.compile(r"(\d+) files?, (\d+) MB unpacked", re.IGNORECASE)
MANIFEST_DIGEST = re.compile(r"[0-9a-fA-F]{32}")
# Set by some tools (e.g. AI coding agents) for the shells they start. It stops
# Windows programs from finding executables in the current folder, and
# unarc.dll starts its decompressors (cls-srep_x64.exe, ...) by bare name from
# there; every compressed volume then fails with "archive data corrupted".
WINE_HOSTILE_VARIABLES = ("NoDefaultCurrentDirectoryInExePath",)


class UnfitError(Exception):
    """Raised for problems unfit can explain better than a traceback."""


@dataclasses.dataclass(frozen=True)
class PackFiles:
    """Files that make up one FitGirl repack."""

    pack_dir: Path
    setup: Path
    bins: tuple[Path, ...]
    bins_manifest: Path


@dataclasses.dataclass(frozen=True)
class Toolchain:
    """External programs unfit drives."""

    wine: Path
    extractor: Path


@dataclasses.dataclass(frozen=True)
class RunOptions:
    """Settings for one extraction run."""

    dest: Path
    log_path: Path
    skip_md5: bool = False
    skip_verify: bool = False
    skip_post_install: bool = False
    verbose: bool = False
    echo: bool = True


class BadFile(NamedTuple):
    """A manifest entry whose digest did not match."""

    path: str
    expected: str
    actual: str


@dataclasses.dataclass(frozen=True)
class Move:
    """A file that belongs at ``target`` but sits at ``source``."""

    source: Path
    target: Path


@dataclasses.dataclass
class VerifyReport:
    """Outcome of hashing a set of files against a manifest."""

    total: int = 0
    ok: list[str] = dataclasses.field(default_factory=list)
    bad: list[BadFile] = dataclasses.field(default_factory=list)
    missing: list[str] = dataclasses.field(default_factory=list)

    @property
    def clean(self) -> bool:
        """Return True when every manifest entry matched.

        Returns:
            True when nothing is bad or missing.
        """
        return not self.bad and not self.missing


class ProgressBar:
    """Single-line progress renderer that can be cleared for log lines."""

    def __init__(self, *, enabled: bool, stream: TextIO | None = None) -> None:
        """Create a bar; ``enabled=False`` makes every call a no-op."""
        self._enabled = enabled
        self._stream = stream if stream is not None else sys.stderr
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """Return True when this bar renders anything.

        Returns:
            The ``enabled`` flag given at construction.
        """
        return self._enabled

    def render(self, done: int, total: int, label: str, start: float) -> None:
        """Draw one progress line for a transfer in progress.

        Args:
            done: Bytes processed so far.
            total: Bytes expected in total.
            label: Text in front of the numbers.
            start: ``time.monotonic()`` when the transfer started.
        """
        if not self._enabled:
            return
        percent = 100.0 if total <= 0 else min(100.0, done * 100.0 / total)
        elapsed = max(time.monotonic() - start, 0.001)
        speed = done / elapsed / (1024 * 1024)
        text = (
            f"{label} {percent:5.1f}% "
            f"{done / 1024**3:6.2f}/{total / 1024**3:6.2f} GiB "
            f"{speed:6.1f} MiB/s"
        )
        with self._lock:
            self._stream.write("\r\033[K" + text)
            self._stream.flush()

    def clear(self) -> None:
        """Erase the current progress line."""
        if not self._enabled:
            return
        with self._lock:
            self._stream.write("\r\033[K")
            self._stream.flush()


def is_safe_relative(relative_path: str) -> bool:
    """Return True when a manifest path stays inside the extraction root.

    Args:
        relative_path: POSIX-style path from a manifest.

    Returns:
        False for absolute paths and paths with ``..``.
    """
    path = PurePosixPath(relative_path)
    return not path.is_absolute() and not any(part == ".." for part in path.parts)


def parse_md5_manifest(text: str) -> dict[str, str]:
    r"""Parse a FitGirl ``*.md5`` manifest into ``relative path -> digest``.

    Entries that would escape the extraction root are dropped: the manifest
    comes from the downloaded pack and is not trusted with paths outside it.

    Args:
        text: Manifest content, with lines like ``<md5> *..\fg-01.bin``.

    Returns:
        Mapping of POSIX-style relative paths to lowercase MD5 digests.
    """
    entries: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        digest, separator, path = line.partition(" ")
        if not separator or not MANIFEST_DIGEST.fullmatch(digest):
            continue
        relative = path.strip().lstrip("*").strip().replace("\\", "/")
        while relative.startswith(("../", "./")):
            relative = relative[3:] if relative.startswith("../") else relative[2:]
        if relative and is_safe_relative(relative):
            entries[relative] = digest.lower()
    return entries


def read_md5_manifest(path: Path) -> dict[str, str]:
    """Read and parse a manifest file, tolerating non-UTF-8 bytes.

    Args:
        path: The ``*.md5`` file.

    Returns:
        Mapping of relative paths to MD5 digests, see :func:`parse_md5_manifest`.
    """
    return parse_md5_manifest(path.read_text(encoding="utf-8", errors="replace"))


def derive_dest_name(pack_dir: Path) -> str:
    """Derive a destination folder name from the repack folder name.

    Trailing bracketed tags such as ``[FitGirl Repack]`` are dropped.

    Args:
        pack_dir: The repack folder.

    Returns:
        The folder name without its tag, or the plain name if nothing is left.
    """
    name = MANIFEST_TAG.sub("", pack_dir.name).strip(" -_")
    return name or pack_dir.name


def parse_unpacked_bytes(listing: str) -> int:
    """Sum the unpacked sizes reported by ``fitgirl-extractor --list``.

    The tool prints one ``N files, X MB unpacked, Y MB packed`` line per
    volume, and reports MiB under an ``MB`` label.

    Args:
        listing: The extractor's listing output.

    Returns:
        The unpacked size in bytes; 0 when no size line was found.
    """
    return sum(
        int(match.group(2)) * 1024 * 1024 for match in LIST_TOTAL.finditer(listing)
    )


def find_setup(pack_dir: Path) -> Path:
    """Locate the repack's ``setup.exe``, whatever its case.

    Args:
        pack_dir: The repack folder.

    Returns:
        The installer.

    Raises:
        UnfitError: If the folder is missing or holds no ``setup.exe``.
    """
    if not pack_dir.is_dir():
        raise UnfitError(f"not a directory: {pack_dir}")
    for entry in sorted(pack_dir.iterdir()):
        if entry.name.lower() == "setup.exe" and entry.is_file():
            return entry
    raise UnfitError(f"no setup.exe in {pack_dir} - is this a FitGirl repack?")


def find_pack_files(pack_dir: Path) -> PackFiles:
    """Locate ``setup.exe``, the ``fg-*.bin`` volumes and the MD5 manifest.

    Args:
        pack_dir: The repack folder.

    Returns:
        The files that make up the repack.

    Raises:
        UnfitError: If the folder is not a recognisable FitGirl repack.
    """
    setup = find_setup(pack_dir)
    bins = tuple(sorted(path for path in pack_dir.glob("fg-*.bin") if path.is_file()))
    if not bins:
        raise UnfitError(f"no fg-*.bin volumes in {pack_dir}")
    manifests = sorted((pack_dir / "MD5").glob("*.md5"))
    if not manifests:
        raise UnfitError(f"no MD5/*.md5 manifest in {pack_dir}")
    return PackFiles(pack_dir, setup, bins, manifests[0])


def is_selective(relative_path: str) -> bool:
    """Return True for optional selective-download volumes.

    Args:
        relative_path: Volume path from the bins manifest.

    Returns:
        True for ``fg-selective-*`` volumes.
    """
    return PurePosixPath(relative_path).name.lower().startswith(SELECTIVE_PREFIX)


def hash_file(path: Path, on_chunk: Callable[[int], None] | None = None) -> str:
    """Return the MD5 hex digest of ``path``.

    Args:
        path: File to hash.
        on_chunk: Called with the size of every chunk read, for progress.

    Returns:
        The lowercase hex digest.
    """
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
            if on_chunk is not None:
                on_chunk(len(chunk))
    return digest.hexdigest()


class ByteProgress:
    """Thread-safe byte counter that redraws a progress line a few times a second."""

    def __init__(self, bar: ProgressBar, total: int, label: str) -> None:
        """Start counting towards ``total`` bytes.

        Args:
            bar: Progress renderer.
            total: Bytes expected in total.
            label: Text in front of the numbers.
        """
        self._bar = bar
        self._total = total
        self._label = label
        self._done = 0
        self._start = time.monotonic()
        self._drawn = 0.0
        self._lock = threading.Lock()

    def add(self, count: int) -> None:
        """Count processed bytes and redraw at most every ``REDRAW_INTERVAL``.

        Args:
            count: Bytes processed since the last call.
        """
        with self._lock:
            self._done += count
            now = time.monotonic()
            if now - self._drawn < REDRAW_INTERVAL:
                return
            self._drawn = now
            done = self._done
        self._bar.render(done, self._total, self._label, self._start)


def verify_against_manifest(
    root: Path,
    manifest: Mapping[str, str],
    bar: ProgressBar | None = None,
) -> VerifyReport:
    """Hash every manifest entry under ``root`` and classify the results.

    Files are hashed ``HASH_WORKERS`` at a time; MD5 releases the GIL, so
    packs made of several large files verify several times faster.

    Args:
        root: Folder the manifest paths are relative to.
        manifest: Mapping of relative paths to expected MD5 digests.
        bar: Progress renderer, or None for no progress.

    Returns:
        Which entries matched, differed or were missing.
    """
    present = {
        relative: root / relative
        for relative in manifest
        if (root / relative).is_file()
    }
    total = sum(path.stat().st_size for path in present.values())
    progress = (
        ByteProgress(bar, total, "verifying")
        if bar is not None and bar.enabled
        else None
    )
    on_chunk = progress.add if progress is not None else None
    with ThreadPoolExecutor(max_workers=HASH_WORKERS) as pool:
        digests = dict(
            zip(
                present,
                pool.map(
                    functools.partial(hash_file, on_chunk=on_chunk), present.values()
                ),
                strict=True,
            )
        )
    if bar is not None:
        bar.clear()
    report = VerifyReport(total=len(manifest))
    for relative, expected in sorted(manifest.items()):
        actual = digests.get(relative)
        if actual is None:
            report.missing.append(relative)
        elif actual == expected:
            report.ok.append(relative)
        else:
            report.bad.append(BadFile(relative, expected, actual))
    return report


def describe_report(report: VerifyReport, *, selective_missing: bool = False) -> str:
    """Render a one-line verification summary.

    Args:
        report: Verification outcome.
        selective_missing: Mention missing selective volumes as ignored.

    Returns:
        A summary such as ``3 ok, 0 bad, 1 missing``.
    """
    summary = (
        f"{len(report.ok)} ok, {len(report.bad)} bad, {len(report.missing)} missing"
    )
    optional = sum(1 for relative in report.missing if is_selective(relative))
    if selective_missing and optional:
        summary += f" ({optional} optional selective volume(s) ignored)"
    return summary


def plan_root_fixups(root: Path, manifest: Mapping[str, str]) -> list[Move]:
    """Find manifest files that unpacked to the root instead of their subfolder.

    Only files whose digest matches the manifest are proposed, so a move can
    never place wrong data.

    Args:
        root: Extraction destination.
        manifest: Mapping from manifest to the expected layout.

    Returns:
        Moves to apply, source and target paths absolute under ``root``.
    """
    moves: list[Move] = []
    for relative, expected in sorted(manifest.items()):
        target = root / relative
        if target.exists():
            continue
        source = root / PurePosixPath(relative).name
        if not source.is_file() or source == target:
            continue
        if hash_file(source) != expected:
            continue
        moves.append(Move(source, target))
    return moves


def apply_moves(moves: Sequence[Move]) -> None:
    """Create parent folders and move each file into place.

    Args:
        moves: Files to move, see :func:`plan_root_fixups`.
    """
    for move in moves:
        move.target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(move.source), str(move.target))


def directory_size(root: Path, exclude: str = ".fgtmp") -> int:
    """Total bytes of regular files under ``root``, skipping ``exclude``.

    Files that disappear while the folder is walked (the extractor writes and
    deletes temporary files) are not counted.

    Args:
        root: Folder to measure.
        exclude: Folder name to skip at any depth.

    Returns:
        The size in bytes.
    """
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name != exclude]
        for filename in filenames:
            with contextlib.suppress(OSError):
                total += os.stat(os.path.join(dirpath, filename)).st_size
    return total


def check_windows_ansi(path: Path) -> None:
    """Reject paths that ``unarc.dll`` cannot represent in the ANSI code page.

    Args:
        path: Path that will be passed to the extractor.

    Raises:
        UnfitError: When the path is not representable in Windows-1252.
    """
    try:
        str(path).encode("cp1252")
    except UnicodeEncodeError as error:
        raise UnfitError(
            "path is not representable in Windows-1252, unarc.dll cannot use it: "
            f"{path}"
        ) from error


def pick_wine(candidates: Sequence[Path]) -> Path | None:
    """Return the first candidate that exists and is executable.

    Args:
        candidates: Wine binaries in order of preference.

    Returns:
        The first usable binary, or None.
    """
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def proton_candidates() -> list[Path]:
    """List ``wine`` binaries from installed Proton runtimes, newest first.

    Returns:
        Proton Experimental first, then other runtimes by modification time.
    """
    roots = [
        Path.home() / ".steam/steam/steamapps/common",
        Path.home() / ".local/share/Steam/steamapps/common",
        Path.home() / ".steam/root/steamapps/common",
    ]
    found: list[tuple[bool, float, Path]] = []
    for root in roots:
        if not root.is_dir():
            continue
        for runtime in root.glob("Proton*"):
            wine = runtime / "files/bin/wine"
            if wine.is_file():
                found.append(
                    (
                        "Experimental" in wine.parents[2].name,
                        runtime.stat().st_mtime,
                        wine,
                    )
                )
    found.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [wine for _, _, wine in found]


def macos_wine_candidates() -> list[Path]:
    """List common ``wine`` binary locations on macOS."""
    candidates = [
        Path("/opt/homebrew/bin/wine"),
        Path("/usr/local/bin/wine"),
    ]
    heroic_root = Path.home() / "Library/Application Support/heroic/tools/wine"
    if heroic_root.is_dir():
        heroic_bins: list[tuple[float, Path]] = []
        for runtime in heroic_root.iterdir():
            wine = runtime / "Contents/Resources/wine/bin/wine"
            if wine.is_file():
                heroic_bins.append((runtime.stat().st_mtime, wine))
        heroic_bins.sort(key=lambda item: item[0], reverse=True)
        candidates.extend(wine for _, wine in heroic_bins)
    for app_dir in (Path("/Applications"), Path.home() / "Applications"):
        for name in ("Wine Stable.app", "Wine Staging.app", "Wine Devel.app"):
            candidates.append(app_dir / name / "Contents/Resources/wine/bin/wine")
    return candidates


def detect_wine(explicit: Path | None) -> Path:
    """Locate a Wine binary and confirm it runs.

    Order: ``--wine``, ``$UNFIT_WINE``, ``wine`` on PATH, then platform
    locations (macOS Wine/Heroic bundles or Linux Proton runtimes).

    Args:
        explicit: The ``--wine`` argument, if given.

    Returns:
        A Wine binary that answers ``--version``.

    Raises:
        UnfitError: If nothing usable is found, or Wine refuses to start.
    """
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    env_wine = os.environ.get("UNFIT_WINE")
    if env_wine:
        candidates.append(Path(env_wine).expanduser())
    on_path = shutil.which("wine")
    if on_path:
        candidates.append(Path(on_path))

    platform_candidates = (
        macos_wine_candidates() if sys.platform == "darwin" else proton_candidates()
    )
    wine = pick_wine(candidates) or pick_wine(platform_candidates)
    if wine is None:
        if sys.platform == "darwin":
            raise UnfitError(
                "no wine found. Install Wine with WoW64 support (e.g. "
                "wine-stable via Homebrew or Heroic's Wine-11.18), or point "
                "unfit at one with --wine / $UNFIT_WINE."
            )
        raise UnfitError(
            "no wine found. Install Wine with WoW64 support, or point unfit at one "
            "with --wine / $UNFIT_WINE (a Proton build works too)."
        )

    result = subprocess.run(
        [str(wine), "--version"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        if (
            sys.platform == "darwin"
            and platform.machine() == "arm64"
            and not Path("/Library/Apple/usr/share/rosetta/rosetta").exists()
        ):
            detail = (
                f"{detail} (Rosetta 2 appears missing; run "
                "`softwareupdate --install-rosetta`)"
            )
        raise UnfitError(f"{wine} does not run: {detail}")
    LOGGER.info("using %s (%s)", wine, result.stdout.strip())
    return wine


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of ``path``.

    Args:
        path: File to hash.

    Returns:
        The lowercase hex digest.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def download_extractor(target: Path) -> None:
    """Download the pinned extractor release and verify its digest.

    Args:
        target: Where to store the extractor.

    Raises:
        UnfitError: When the download fails or the digest does not match.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".part")
    print(f"downloading fitgirl-extractor {EXTRACTOR_VERSION}", flush=True)
    try:
        with urllib.request.urlopen(EXTRACTOR_URL, timeout=120) as response:  # noqa: S310
            temporary.write_bytes(response.read())
    except (urllib.error.URLError, OSError) as error:
        temporary.unlink(missing_ok=True)
        raise UnfitError(f"cannot download {EXTRACTOR_URL}: {error}") from error

    actual = sha256_file(temporary)
    if actual != EXTRACTOR_SHA256:
        temporary.unlink(missing_ok=True)
        raise UnfitError(
            f"downloaded extractor has SHA-256 {actual}, expected {EXTRACTOR_SHA256}"
        )
    temporary.replace(target)
    target.chmod(0o755)


def ensure_extractor(explicit: Path | None) -> Path:
    """Return a usable extractor path, fetching the pinned build if needed.

    Order: ``--extractor``, ``$UNFIT_EXTRACTOR``, then the cached download, which
    is fetched again when missing or when its checksum fails.

    Args:
        explicit: The ``--extractor`` argument, if given.

    Returns:
        Path to ``fitgirl-extractor.exe``.

    Raises:
        UnfitError: When an explicit path is missing or the download fails.
    """
    env_path = os.environ.get("UNFIT_EXTRACTOR")
    if explicit is not None:
        candidate = explicit.expanduser()
    elif env_path:
        candidate = Path(env_path).expanduser()
    else:
        candidate = EXTRACTOR_PATH
    if candidate.is_file():
        if (
            explicit is None
            and not env_path
            and sha256_file(candidate) != EXTRACTOR_SHA256
        ):
            LOGGER.warning("cached extractor failed its checksum, fetching it again")
            download_extractor(candidate)
        return candidate
    if explicit is not None or env_path:
        raise UnfitError(f"extractor not found: {candidate}")
    download_extractor(candidate)
    return candidate


@dataclasses.dataclass(frozen=True)
class ExtractFlags:
    """Switches for one ``fitgirl-extractor`` run."""

    list_only: bool = False
    skip_bin_check: bool = False
    skip_verify: bool = False
    verbose: bool = False
    only: tuple[str, ...] = ()


def build_extract_command(
    tools: Toolchain, pack_dir: Path, dest: Path | None, flags: ExtractFlags
) -> list[str]:
    """Assemble the extractor command line for Wine.

    Args:
        tools: Wine and the extractor to run.
        pack_dir: Folder with ``setup.exe`` and the volumes.
        dest: Destination; ignored for listings.
        flags: Extractor switches.

    Returns:
        The command as a list of arguments.
    """
    command = [str(tools.wine), str(tools.extractor), str(pack_dir)]
    if dest is not None and not flags.list_only:
        command.extend(["-d", str(dest)])
    if flags.list_only:
        command.append("--list")
    for volume in flags.only:
        command.extend(["--only", volume])
    if flags.skip_bin_check:
        command.append("--skip-bin-check")
    if flags.skip_verify:
        command.append("--skip-verify")
    if flags.verbose:
        command.append("--verbose")
    return command


def wine_environment() -> dict[str, str]:
    """Environment for the extractor: persistent prefix, quiet Wine.

    Wine passes Unix variables on to Windows programs, so
    :data:`WINE_HOSTILE_VARIABLES` are removed.

    Returns:
        A copy of the current environment with ``WINEPREFIX`` and ``WINEDEBUG``.
    """
    environment = dict(os.environ)
    environment["WINEPREFIX"] = str(PREFIX_DIR)
    environment["WINEDEBUG"] = "-all"
    for name in WINE_HOSTILE_VARIABLES:
        environment.pop(name, None)
    return environment


def stop_process_group(process: subprocess.Popen[str]) -> None:
    """Stop a child started with ``start_new_session`` and everything it spawned.

    Sends SIGTERM to the group, waits up to 30 seconds, then sends SIGKILL.
    A group that already exited is not an error.

    Args:
        process: The child process.
    """
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired, ProcessLookupError):
        process.wait(timeout=30)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


@dataclasses.dataclass(frozen=True)
class ProgressTarget:
    """What to measure for the progress line: a folder growing towards a size."""

    bar: ProgressBar
    dest: Path
    total: int


def watch_progress(progress: ProgressTarget, stop: threading.Event) -> None:
    """Redraw the progress line from the folder size until ``stop`` is set.

    Args:
        progress: Folder to measure and the size it grows towards.
        stop: Set when the command has ended.
    """
    start = time.monotonic()
    while not stop.wait(PROGRESS_INTERVAL):
        size = directory_size(progress.dest)
        progress.bar.render(size, progress.total, "unpacking", start)


def relay_output(
    lines: Iterable[str],
    log: TextIO,
    *,
    bar: ProgressBar | None,
    echo: bool,
    on_line: Callable[[str], None] | None,
) -> None:
    """Copy command output to the log, the terminal and a callback.

    Args:
        lines: Output lines of the command.
        log: Open run log.
        bar: Progress line to clear before each echoed line, if any.
        echo: Copy the output to stdout.
        on_line: Called with every output line.
    """
    for line in lines:
        if bar is not None:
            bar.clear()
        log.write(line)
        if echo:
            sys.stdout.write(line)
            sys.stdout.flush()
        if on_line is not None:
            on_line(line)


def run_streaming(
    command: Sequence[str],
    log_path: Path,
    *,
    progress: ProgressTarget | None = None,
    echo: bool = True,
    on_line: Callable[[str], None] | None = None,
) -> int:
    """Run the extractor, log its output, echo and show progress as asked.

    The child gets its own process group so Ctrl-C reaches Wine and every
    helper process it spawned.

    Args:
        command: Command line to run under the unfit Wine prefix.
        log_path: Log file the command and its output are appended to.
        progress: Folder to measure for the progress line, if any.
        echo: Copy the output to stdout.
        on_line: Called with every output line.

    Returns:
        The command's exit code.

    Raises:
        UnfitError: When the output cannot be read.
    """
    bar = progress.bar if progress is not None and progress.bar.enabled else None
    stop = threading.Event()
    watcher = (
        threading.Thread(target=watch_progress, args=(progress, stop), daemon=True)
        if bar is not None
        else None
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8", errors="replace") as log:
        log.write(f"$ WINEPREFIX={PREFIX_DIR} {shlex.join(list(command))}\n")
        process = subprocess.Popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            errors="replace",
            bufsize=1,
            env=wine_environment(),
            start_new_session=True,
        )
        if process.stdout is None:
            process.kill()
            raise UnfitError(f"cannot read the output of {command[0]}")
        if watcher is not None:
            watcher.start()
        try:
            relay_output(process.stdout, log, bar=bar, echo=echo, on_line=on_line)
            returncode = process.wait()
        except KeyboardInterrupt:
            stop_process_group(process)
            raise
        finally:
            stop.set()
            if watcher is not None:
                watcher.join(timeout=PROGRESS_INTERVAL + 1)
            if bar is not None:
                bar.clear()
    return returncode


def verify_bins(pack: PackFiles, bar: ProgressBar) -> VerifyReport:
    """Verify the ``.bin`` volumes against the repack's bins manifest.

    Args:
        pack: The repack.
        bar: Progress renderer for hashing.

    Returns:
        Which volumes matched, differed or were missing.
    """
    manifest = read_md5_manifest(pack.bins_manifest)
    report = verify_against_manifest(pack.pack_dir, manifest, bar)
    for relative in report.ok:
        print(f"  {relative}: ok")
    for entry in report.bad:
        print(
            f"  {entry.path}: MISMATCH (expected {entry.expected}, got {entry.actual})"
        )
    for relative in report.missing:
        label = "missing (selective, ignored)" if is_selective(relative) else "MISSING"
        print(f"  {relative}: {label}")
    return report


def required_missing(report: VerifyReport) -> list[str]:
    """Missing volumes that are not optional selective downloads.

    Args:
        report: Volume verification outcome.

    Returns:
        Missing volumes that block unpacking.
    """
    return [relative for relative in report.missing if not is_selective(relative)]


def destination_manifest(dest: Path) -> dict[str, str] | None:
    """Read ``_Redist/fitgirl.md5`` from an unpacked folder, if it has one.

    Args:
        dest: Unpacked folder.

    Returns:
        The parsed manifest, or None when the folder has no manifest.
    """
    manifest_path = dest / "_Redist/fitgirl.md5"
    if not manifest_path.is_file():
        return None
    return read_md5_manifest(manifest_path)


def repair_layout(dest: Path) -> None:
    """Move manifest files that unpacked to the root into their subfolder.

    Args:
        dest: Unpacked folder.
    """
    manifest = destination_manifest(dest)
    if manifest is None:
        return
    moves = plan_root_fixups(dest, manifest)
    for move in moves:
        print(
            f"repairing layout: {move.source.name} -> {move.target.relative_to(dest)}"
        )
    apply_moves(moves)


def post_extract_verify(dest: Path, bar: ProgressBar) -> int:
    """Repair misplaced files, then verify the destination against FitGirl's list.

    Args:
        dest: Unpacked folder.
        bar: Progress renderer for hashing.

    Returns:
        Process exit code: 0 when everything verified, 1 otherwise.
    """
    manifest = destination_manifest(dest)
    if manifest is None:
        print(
            "no _Redist/fitgirl.md5 to verify against; skipping post-extraction check"
        )
        return 0

    repair_layout(dest)
    report = verify_against_manifest(dest, manifest, bar)
    print(f"verified {report.total} files: {describe_report(report)}")
    for entry in report.bad:
        print(f"  BAD     {entry.path}: expected {entry.expected}, got {entry.actual}")
    for relative in report.missing:
        print(f"  MISSING {relative}")
    return 0 if report.clean else 1


# --- FitGirl post-install scripts -------------------------------------------
#
# Some repacks store data in a smaller form and rebuild it after unpacking with
# batch scripts in ``work\work\`` (``build01.bat`` ...). A typical chain turns
# every packed video file back into the original with ``fgpack.exe`` and an
# xdelta patch (``x.exe``), then ``raw.exe`` copies the files into an archive at
# fixed offsets. The scripts come from the pack, so they are not executed: unfit
# parses them, accepts only the commands below, and replays them itself.

SCRIPT_PLACEHOLDER = re.compile(r"^fitgirl\d*-path\\", re.IGNORECASE)
SCRIPT_GLOB = re.compile(r"^build\d*\.bat$", re.IGNORECASE)
POST_INSTALL_TOOLS = frozenset({"fgpack.exe", "x.exe", "raw.exe", "run.exe"})
INSTALLER_TOOLS = frozenset({"x5.exe", "x2n.exe"})
TOOL_NOISE = re.compile(
    r"^(?:[0-9a-f]{4}:(?:fixme|err|warn|trace):|WARNING: radv is not a conformant)",
    re.IGNORECASE,
)
HPATCH_OPTION = re.compile(r"^-(?:m|s(?:-\d+[kmg]?)?)$", re.IGNORECASE)
SYNC_TOOLS = frozenset({"countdown.exe"})
WAIT_MARKER = re.compile(r'^if\s+not\s+exist\s+"?([^"\s]+)"?\s+goto\s', re.IGNORECASE)
ECHO_REDIRECT = re.compile(r'>>?\s*"?([^"\s>]+)"?\s*$')
TRASH_DIR = ".unfit-trash"
SKIP_DIRS = frozenset({".fgtmp", TRASH_DIR})
SCRIPT_SEARCH_DEPTH = 3


class Step(NamedTuple):
    """One command of a post-install chain: a tool name and its raw arguments."""

    tool: str
    args: tuple[str, ...]
    exe: str = ""


@dataclasses.dataclass(frozen=True)
class Chain:
    """Commands joined by ``&&``: run in order, stop at the first failure."""

    origin: str
    steps: tuple[Step, ...]


@dataclasses.dataclass(frozen=True)
class Batch:
    """Chains from one script line; ``run.exe`` lists run in parallel."""

    origin: str
    chains: tuple[Chain, ...]
    parallel: bool


@dataclasses.dataclass(frozen=True)
class StepFiles:
    """Files a step reads and writes, as written in the script."""

    inputs: tuple[str, ...]
    outputs: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class PostInstallContext:
    """Where the scripts live and which programs replay them."""

    root: Path
    scripts_root: Path
    wine: Path
    xdelta: Path
    windows_root: str
    installer_tools: Path | None = None


def split_cmd_words(text: str) -> list[str]:
    """Split a ``cmd.exe`` command line into words, honouring double quotes.

    Args:
        text: One command.

    Returns:
        The words with quotes removed; ``""`` gives an empty word.
    """
    words: list[str] = []
    current: list[str] = []
    quoted = False
    started = False
    for char in text:
        if char == '"':
            quoted = not quoted
            started = True
        elif char.isspace() and not quoted:
            if started or current:
                words.append("".join(current))
            current, started = [], False
        else:
            current.append(char)
    if started or current:
        words.append("".join(current))
    return words


def split_and_chain(text: str) -> list[str]:
    """Split ``a && b && c`` on ``&&`` outside double quotes.

    Args:
        text: A command chain.

    Returns:
        The non-empty commands, stripped.
    """
    parts: list[str] = []
    start = 0
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            quoted = not quoted
        elif not quoted and text.startswith("&&", index):
            parts.append(text[start:index].strip())
            start = index + 2
            index += 1
        index += 1
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def is_placeholder_path(argument: str) -> bool:
    r"""Return True for ``fitgirl2-path\...`` arguments (the scripts folder).

    Args:
        argument: One script argument.

    Returns:
        True when the argument starts with the scripts-folder placeholder.
    """
    return bool(SCRIPT_PLACEHOLDER.match(argument))


def strip_placeholder(argument: str) -> str:
    r"""Drop a leading ``fitgirl2-path\`` so the rest is relative to the scripts root.

    Args:
        argument: One script argument.

    Returns:
        The argument without the placeholder; unchanged when it has none.
    """
    return SCRIPT_PLACEHOLDER.sub("", argument)


def raw_options(args: Sequence[str]) -> tuple[list[str], dict[str, int]]:
    """Split ``raw.exe`` arguments into positionals and ``-ioff/-ilen/-ooff``.

    Args:
        args: Arguments after ``raw.exe``.

    Returns:
        The positional arguments and the numeric options by name.

    Raises:
        UnfitError: For unknown options or options without a number.
    """
    positional: list[str] = []
    options: dict[str, int] = {}
    for argument in args:
        if argument.startswith("-"):
            name, separator, value = argument[1:].partition("=")
            name = name.lower()
            if name not in {"ioff", "ilen", "ooff"} or not separator:
                raise UnfitError(f"unsupported raw.exe option {argument}")
            if not value.isdigit():
                raise UnfitError(f"raw.exe option {argument} is not a number")
            options[name] = int(value)
        else:
            positional.append(argument)
    return positional, options


def xdelta_operands(args: Sequence[str]) -> tuple[str, str, str]:
    """Return ``(source, patch, output)`` for an ``x.exe -d -s`` decode.

    Args:
        args: Arguments after ``x.exe``.

    Returns:
        The source file, the patch and the output file.

    Raises:
        UnfitError: When the arguments are not a ``-d -s`` decode.
    """
    positional: list[str] = []
    source: str | None = None
    decode = False
    iterator = iter(args)
    for argument in iterator:
        if argument == "-s":
            source = next(iterator, None)
        elif argument == "-d":
            decode = True
        elif argument != "-f":
            if argument.startswith("-"):
                raise UnfitError(f"unsupported x.exe option {argument}")
            positional.append(argument)
    if not decode or source is None or len(positional) != 2:
        raise UnfitError("x.exe is only supported as 'x.exe -d -s SOURCE PATCH OUT'")
    return source, positional[0], positional[1]


def hpatch_operands(args: Sequence[str]) -> tuple[str, str, str]:
    """Return ``(old, diff, new)`` for an ``x5.exe`` (HDiffPatch ``hpatchz``) call.

    Args:
        args: Arguments after ``x5.exe``.

    Returns:
        The old file, the diff and the file to create.

    Raises:
        UnfitError: For options other than ``-m``/``-s[-SIZE]`` or a wrong count.
    """
    positional: list[str] = []
    for argument in args:
        if argument.startswith("-"):
            if not HPATCH_OPTION.match(argument):
                raise UnfitError(f"unsupported x5.exe option {argument}")
        else:
            positional.append(argument)
    if len(positional) != 3:
        raise UnfitError("x5.exe takes exactly 'OLD DIFF NEW' after its options")
    return positional[0], positional[1], positional[2]


def step_files(step: Step) -> StepFiles:
    """Validate a step and report the files it reads and writes.

    Args:
        step: One parsed command.

    Returns:
        The files as written in the script.

    Raises:
        UnfitError: When the tool is unknown or its arguments do not fit.
    """
    if step.tool == "del":
        return StepFiles((), ())
    if step.tool == "fgpack.exe":
        if len(step.args) != 2:
            raise UnfitError("fgpack.exe takes exactly 'INPUT OUTPUT'")
        return StepFiles((step.args[0],), (step.args[1],))
    if step.tool == "x.exe":
        source, patch, output = xdelta_operands(step.args)
        return StepFiles((source, patch), (output,))
    if step.tool == "raw.exe":
        positional, _ = raw_options(step.args)
        if len(positional) != 2:
            raise UnfitError("raw.exe takes exactly 'INPUT OUTPUT [options]'")
        return StepFiles((positional[0],), (positional[1],))
    if step.tool == "x5.exe":
        old, diff, new = hpatch_operands(step.args)
        return StepFiles((old, diff), (new,))
    if step.tool == "x2n.exe":
        if len(step.args) != 3 or any(arg.startswith("-") for arg in step.args):
            raise UnfitError("x2n.exe takes exactly 'TARGET DATA MAP'")
        return StepFiles(tuple(step.args), (step.args[0],))
    raise UnfitError(f"unsupported post-install tool {step.tool}")


def check_script_path(argument: str) -> None:
    """Reject absolute paths and ``..`` so a script cannot leave the game folder.

    Args:
        argument: A file argument from a script.

    Raises:
        UnfitError: For paths that could point outside the destination.
    """
    pure = PureWindowsPath(strip_placeholder(argument))
    if pure.drive or pure.root or ".." in pure.parts or not pure.parts:
        raise UnfitError(f"path not allowed in a post-install script: {argument}")


def parse_step(text: str, origin: str) -> Step:
    """Turn one command into a :class:`Step`, rejecting anything unknown.

    Args:
        text: One command without ``&&``.
        origin: ``script:line`` for error messages.

    Returns:
        The parsed step.

    Raises:
        UnfitError: For unknown programs, wildcards or unsafe paths.
    """
    words = split_cmd_words(text)
    if not words:
        raise UnfitError(f"{origin}: empty command")
    head, args = words[0], tuple(words[1:])
    if head.lower() == "del":
        # Scripts delete themselves and their helpers when done; unfit keeps
        # them so ``--finish`` can replay, so those targets are dropped here.
        targets = tuple(
            arg
            for arg in args
            if not arg.startswith("/") and not is_placeholder_path(arg)
        )
        if any(char in arg for arg in targets for char in "*?"):
            raise UnfitError(f"{origin}: wildcard deletes are not supported: {text}")
        try:
            for target in targets:
                check_script_path(target)
        except UnfitError as error:
            raise UnfitError(f"{origin}: {error}: {text}") from error
        return Step("del", targets)
    name = PureWindowsPath(head).name.lower()
    if name in POST_INSTALL_TOOLS | SYNC_TOOLS and is_placeholder_path(head):
        step = Step(name, args, head)
        if name in POST_INSTALL_TOOLS - {"run.exe"}:
            try:
                files = step_files(step)
                for operand in (head, *files.inputs, *files.outputs):
                    check_script_path(operand)
            except UnfitError as error:
                raise UnfitError(f"{origin}: {error}: {text}") from error
        return step
    raise UnfitError(f"{origin}: unsupported post-install command: {text}")


def is_control_line(line: str) -> bool:
    """Return True for lines that need no replay: labels, gotos and waits.

    FitGirl's scripts poll for each other's marker files because the installer
    starts them together; unfit runs them one after another instead.

    Args:
        line: One stripped script line.

    Returns:
        True for empty lines, comments, labels, ``goto`` and ``if ... goto``.
    """
    lowered = line.lower()
    return (
        not line
        or line.startswith(":")
        or lowered in {"rem", "@echo off", "echo off"}
        or lowered.startswith(("rem ", "goto ", "@rem "))
        or (lowered.startswith("if ") and " goto " in f"{lowered} ")
    )


def wait_markers(scripts: Sequence[Path]) -> frozenset[str]:
    """Collect the files scripts wait for with ``if not exist FILE goto``.

    Args:
        scripts: The ``build*.bat`` files of one pack.

    Returns:
        Lowercase file names that act as synchronisation markers.
    """
    markers: set[str] = set()
    for script in scripts:
        text = script.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            match = WAIT_MARKER.match(line.strip())
            if match:
                markers.add(PureWindowsPath(match.group(1)).name.lower())
    return frozenset(markers)


def check_echo(line: str, origin: str, markers: frozenset[str]) -> None:
    """Accept an ``echo`` that only prints or writes a marker another script waits for.

    Args:
        line: One stripped script line starting with ``echo``.
        origin: ``script:line`` for error messages.
        markers: File names from :func:`wait_markers`.

    Raises:
        UnfitError: When the echo writes any other file, which unfit cannot replay.
    """
    match = ECHO_REDIRECT.search(line)
    if match and PureWindowsPath(match.group(1)).name.lower() not in markers:
        raise UnfitError(f"{origin}: echo writes a file unfit does not replay: {line}")


def parse_chain_text(line: str, origin: str) -> list[Step]:
    """Parse ``cmd /c "a && b"`` or a plain command into steps.

    Deletes that only target the scripts folder are dropped.

    Args:
        line: One script line.
        origin: ``script:line`` for error messages.

    Returns:
        The steps in order; empty when nothing is left to run.

    Raises:
        UnfitError: From :func:`parse_step`.
    """
    text = line.strip()
    if text.lower().startswith("cmd /c "):
        text = text[7:].strip()
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            text = text[1:-1]
    steps = [parse_step(part, origin) for part in split_and_chain(text)]
    return [step for step in steps if step.tool != "del" or step.args]


def parse_post_install_script(
    script: Path, scripts_root: Path, markers: frozenset[str]
) -> list[Batch]:
    """Parse one ``build*.bat`` into batches, expanding ``run.exe`` lists.

    Args:
        script: The batch file to parse.
        scripts_root: Folder the ``fitgirl2-path`` placeholder stands for.
        markers: Wait-marker file names from :func:`wait_markers`.

    Returns:
        The script's batches in order.

    Raises:
        UnfitError: On any command unfit does not know how to replay.
    """
    batches: list[Batch] = []
    lines = script.read_text(encoding="utf-8", errors="replace").splitlines()
    for number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        origin = f"{script.name}:{number}"
        if is_control_line(line):
            continue
        if line.lower().startswith(("echo ", "@echo ")):
            check_echo(line, origin, markers)
            continue
        steps = parse_chain_text(line, origin)
        if not steps or (len(steps) == 1 and steps[0].tool in SYNC_TOOLS):
            continue
        if any(step.tool in SYNC_TOOLS for step in steps):
            raise UnfitError(f"{origin}: unexpected wait inside a chain: {line}")
        run_steps = [step for step in steps if step.tool == "run.exe"]
        if run_steps:
            if len(steps) != 1:
                raise UnfitError(f"{origin}: run.exe inside a chain: {line}")
            batches.append(parse_run_list(steps[0], origin, scripts_root))
            continue
        batches.append(Batch(origin, (Chain(origin, tuple(steps)),), parallel=False))
    return batches


def parse_run_list(step: Step, origin: str, scripts_root: Path) -> Batch:
    """Expand ``run.exe " " URL LISTFILE N``: one chain per list line.

    Args:
        step: The parsed ``run.exe`` step.
        origin: ``script:line`` for error messages.
        scripts_root: Folder the ``fitgirl2-path`` placeholder stands for.

    Returns:
        A parallel batch with one chain per non-empty list line.

    Raises:
        UnfitError: When the list is missing or holds unsupported commands.
    """
    lists = [arg for arg in step.args if is_placeholder_path(arg)]
    if len(lists) != 1:
        raise UnfitError(f"{origin}: cannot find the command list for run.exe")
    list_path = resolve_case_insensitive(scripts_root, strip_placeholder(lists[0]))
    if not list_path.is_file():
        raise UnfitError(f"{origin}: run.exe list {lists[0]} is missing")
    chains: list[Chain] = []
    text = list_path.read_text(encoding="utf-8", errors="replace")
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        line_origin = f"{list_path.name}:{number}"
        steps = parse_chain_text(line, line_origin)
        if not steps:
            continue
        if any(item.tool in SYNC_TOOLS | {"run.exe"} for item in steps):
            raise UnfitError(f"{line_origin}: unsupported command in run list")
        chains.append(Chain(line_origin, tuple(steps)))
    return Batch(origin, tuple(chains), parallel=True)


def resolve_case_insensitive(base: Path, relative: str) -> Path:
    """Resolve a Windows-style relative path below ``base`` like Windows would.

    Existing components are matched without regard to case; missing ones are
    kept as written so outputs can be created.

    Args:
        base: Folder the path is relative to.
        relative: Windows-style relative path.

    Returns:
        The resolved path, which may not exist yet.

    Raises:
        UnfitError: For absolute paths or ``..`` components.
    """
    pure = PureWindowsPath(relative)
    if pure.drive or pure.root:
        raise UnfitError(f"absolute path in post-install script: {relative}")
    current = base
    for part in pure.parts:
        if part == ".":
            continue
        if part == "..":
            raise UnfitError(f"'..' in post-install script path: {relative}")
        candidate = current / part
        if not candidate.exists() and current.is_dir():
            lowered = part.lower()
            for entry in current.iterdir():
                if entry.name.lower() == lowered:
                    candidate = entry
                    break
        current = candidate
    return current


def find_post_install_scripts(root: Path) -> tuple[Path, list[Path]] | None:
    """Locate the ``work`` folder holding ``build*.bat`` scripts.

    Args:
        root: Unpacked folder.

    Returns:
        ``(scripts_root, scripts)`` where ``scripts_root`` is what the
        ``fitgirl2-path`` placeholder stands for, or None when there are none.

    Raises:
        UnfitError: When more than one candidate folder exists.
    """
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).relative_to(root).parts)
        if depth >= SCRIPT_SEARCH_DEPTH:
            dirnames[:] = []
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        if Path(dirpath).name.lower() != "work" or depth < 1:
            continue
        scripts = sorted(
            (Path(dirpath) / name for name in filenames if SCRIPT_GLOB.match(name)),
            key=lambda path: path.name.lower(),
        )
        if scripts:
            found.extend(scripts)
    if not found:
        return None
    folders = {script.parent for script in found}
    if len(folders) > 1:
        listing = ", ".join(str(item.relative_to(root)) for item in sorted(folders))
        raise UnfitError(f"several post-install script folders: {listing}")
    folder = folders.pop()
    return folder.parent, found


class FileIndex:
    """Case-insensitive index of files under the destination, by file name."""

    def __init__(self, root: Path) -> None:
        """Index every file under ``root``, skipping unfit's scratch folders."""
        self._root = root
        self._by_name: dict[str, list[str]] = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
            relative_dir = Path(dirpath).relative_to(root).as_posix()
            for filename in filenames:
                relative = (
                    filename if relative_dir == "." else f"{relative_dir}/{filename}"
                )
                self._by_name.setdefault(filename.lower(), []).append(relative)

    def folders_holding(self, relative: str) -> set[str]:
        """Folders ``d`` (relative to root) where ``d/relative`` is a file.

        Args:
            relative: Windows-style relative path from a script.

        Returns:
            Matching folders relative to the root; ``""`` stands for the root.
        """
        parts = [part.lower() for part in PureWindowsPath(relative).parts]
        if not parts:
            return set()
        suffix = "/".join(parts)
        folders: set[str] = set()
        for candidate in self._by_name.get(parts[-1], []):
            lowered = candidate.lower()
            if lowered == suffix:
                folders.add("")
            elif lowered.endswith("/" + suffix):
                folders.add(candidate[: len(candidate) - len(suffix) - 1])
        return folders


def chain_probes(chain: Chain) -> list[str]:
    """Return the inputs a chain needs that no earlier step creates.

    Args:
        chain: The chain to inspect.

    Returns:
        The input paths as written in the script.
    """
    produced: set[str] = set()
    probes: list[str] = []
    for step in chain.steps:
        files = step_files(step)
        for name in files.inputs:
            key = PureWindowsPath(name).as_posix().lower()
            if key not in produced and not is_placeholder_path(name):
                probes.append(name)
        produced.update(
            PureWindowsPath(name).as_posix().lower() for name in files.outputs
        )
    return probes


def chain_folders(index: FileIndex, chain: Chain) -> set[str]:
    """Find every folder a chain could have been written for.

    The installer starts each script in a folder the script never names, so
    a candidate is a folder that holds every input the chain reads.
    Delete-only chains use whichever of their targets still exist.

    Args:
        index: Files under the destination.
        chain: The chain to place.

    Returns:
        Candidate folders relative to the destination; empty when the inputs
        are gone (typically because the chain already ran).
    """
    probes = chain_probes(chain)
    if probes:
        sets = [index.folders_holding(probe) for probe in probes]
    else:
        targets = [target for step in chain.steps for target in step.args]
        sets = [found for found in map(index.folders_holding, targets) if found]
    return set.intersection(*sets) if sets else set()


def locate_chain(index: FileIndex, chain: Chain) -> str | None:
    """Find the one working folder a chain was written for.

    Args:
        index: Files under the destination.
        chain: The chain to place.

    Returns:
        The folder relative to the destination, or None when the inputs are
        gone.

    Raises:
        UnfitError: When several folders fit.
    """
    folders = chain_folders(index, chain)
    if len(folders) > 1:
        listing = ", ".join(sorted(folder or "." for folder in folders))
        raise UnfitError(f"{chain.origin}: inputs found in several folders: {listing}")
    return folders.pop() if folders else None


def probes_exist(folder: Path, chain: Chain) -> bool:
    """Check a located folder against the disk, in case the index is stale.

    Args:
        folder: Candidate working folder.
        chain: The chain to place.

    Returns:
        True when every input of the chain exists in ``folder``.
    """
    return all(
        resolve_case_insensitive(folder, probe).is_file()
        for probe in chain_probes(chain)
    )


def windows_path(wine: Path, path: Path) -> str:
    r"""Ask Wine how a Linux path looks to Windows programs.

    Args:
        wine: The Wine binary.
        path: An absolute Linux path.

    Returns:
        The Windows spelling, e.g. ``Z:\games\pack``.

    Raises:
        UnfitError: When ``winepath`` fails or prints nothing.
    """
    result = subprocess.run(
        [str(wine), "winepath.exe", "-w", str(path)],
        env=wine_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    lines = result.stdout.strip().splitlines()
    if result.returncode != 0 or not lines:
        raise UnfitError(f"winepath cannot map {path}: {result.stderr.strip()}")
    return lines[-1].strip()


def remove_tree(path: Path) -> bool:
    """Delete a folder, logging instead of hiding a failure.

    Args:
        path: Folder to delete; a missing folder counts as removed.

    Returns:
        True when the folder is gone.
    """
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return True
    except OSError as error:
        LOGGER.warning("could not remove %s: %s", path, error)
        return False
    return True


def raw_copy(source: Path, target: Path, options: Mapping[str, int]) -> None:
    """Do what ``raw.exe IN OUT -ioff -ilen -ooff`` does, without truncating OUT.

    Args:
        source: File to read.
        target: File to write into; created when missing.
        options: ``ioff``, ``ilen`` and ``ooff`` in bytes.

    Raises:
        UnfitError: When the source is shorter than the requested range.
    """
    input_offset = options.get("ioff", 0)
    output_offset = options.get("ooff", 0)
    remaining = options.get("ilen", max(source.stat().st_size - input_offset, 0))
    target.touch(exist_ok=True)
    with source.open("rb") as reader, target.open("r+b") as writer:
        reader.seek(input_offset)
        writer.seek(output_offset)
        while remaining > 0:
            chunk = reader.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise UnfitError(f"{source.name} is shorter than raw.exe expects")
            writer.write(chunk)
            remaining -= len(chunk)


def run_tool(command: Sequence[str], cwd: Path, *, wine: bool) -> None:
    """Run one helper program and raise with its output when it fails.

    Args:
        command: Command line; under Wine the second item is the program.
        cwd: Working folder.
        wine: Run with the unfit Wine environment.

    Raises:
        UnfitError: When the program exits with a non-zero code.
    """
    result = subprocess.run(
        list(command),
        cwd=cwd,
        env=wine_environment() if wine else None,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        lines = (result.stdout + result.stderr).splitlines()
        output = [
            line.strip()
            for line in lines
            if line.strip() and not TOOL_NOISE.match(line.strip())
        ][-3:]
        tool = PureWindowsPath(command[1]).name if wine else Path(command[0]).name
        raise UnfitError(
            f"{tool} exited with {result.returncode}: {' | '.join(output)}"
        )


class ChainRunner:
    """Replays one chain inside its working folder."""

    def __init__(self, context: PostInstallContext, cwd: Path, trash: Path) -> None:
        """Bind the chain to its folder and a private folder for deleted files."""
        self._context = context
        self._cwd = cwd
        self._trash = trash
        self._deleted = 0

    def path(self, argument: str) -> Path:
        """Resolve a script argument and make sure it stays inside the game.

        Args:
            argument: A file argument from the script.

        Returns:
            The resolved path below the destination.

        Raises:
            UnfitError: When the path would leave the destination.
        """
        if is_placeholder_path(argument):
            base = self._context.scripts_root
            relative = strip_placeholder(argument)
        else:
            base, relative = self._cwd, argument
        resolved = resolve_case_insensitive(base, relative)
        root = self._context.root.resolve()
        absolute = resolved.resolve()
        if absolute != root and root not in absolute.parents:
            raise UnfitError(f"post-install path leaves the destination: {argument}")
        return resolved

    def windows(self, path: Path) -> str:
        """Spell a path inside the destination for a program running under Wine.

        Args:
            path: A path below the destination.

        Returns:
            The Windows spelling, based on what ``winepath`` reported for the root.
        """
        relative = path.relative_to(self._context.root)
        return "\\".join([self._context.windows_root, *relative.parts])

    def run(self, chain: Chain) -> None:
        """Run every step; on success, drop the files the chain deleted.

        Args:
            chain: The chain to run.

        Raises:
            UnfitError: When a step fails; deleted files stay in the trash folder.
        """
        for step in chain.steps:
            try:
                self.run_step(step)
            except (UnfitError, OSError) as error:
                kept = f"; deleted files kept in {self._trash}" if self._deleted else ""
                raise UnfitError(f"{chain.origin}: {error}{kept}") from error
        if self._deleted:
            remove_tree(self._trash)

    def run_step(self, step: Step) -> None:
        """Replay one command.

        Args:
            step: The command to replay.

        Raises:
            UnfitError: When the command fails or is not supported.
        """
        if step.tool == "del":
            self.delete(step.args)
        elif step.tool == "raw.exe":
            positional, options = raw_options(step.args)
            raw_copy(self.path(positional[0]), self.path(positional[1]), options)
        elif step.tool == "fgpack.exe":
            source, target = (self.path(arg) for arg in step.args)
            run_tool(
                [
                    str(self._context.wine),
                    self.windows(self.path(step.exe)),
                    self.windows(source),
                    self.windows(target),
                ],
                self._cwd,
                wine=True,
            )
            if not target.is_file():
                raise UnfitError(f"fgpack.exe did not write {target.name}")
        elif step.tool == "x.exe":
            self.xdelta(step)
        elif step.tool in INSTALLER_TOOLS:
            self.installer_tool(step)
        else:
            raise UnfitError(f"unsupported post-install tool {step.tool}")

    def installer_tool(self, step: Step) -> None:
        """Run a helper unpacked from ``setup.exe`` under Wine.

        ``x5.exe`` (hpatchz) refuses to overwrite its output, so a file left by
        an interrupted run is moved to the trash first.

        Args:
            step: An ``x5.exe`` or ``x2n.exe`` step.

        Raises:
            UnfitError: When the tool is missing, fails or writes nothing.
        """
        tools = self._context.installer_tools
        if tools is None:
            raise UnfitError(f"{step.tool} was not unpacked from setup.exe")
        files = step_files(step)
        if step.tool == "x5.exe":
            self.delete(files.outputs)
        options = [arg for arg in step.args if arg.startswith("-")]
        operands = [
            self.windows(self.path(arg)) for arg in step.args if not arg.startswith("-")
        ]
        program = self.windows(resolve_case_insensitive(tools, step.tool))
        run_tool(
            [str(self._context.wine), program, *options, *operands],
            self._cwd,
            wine=True,
        )
        for output in files.outputs:
            if not self.path(output).is_file():
                raise UnfitError(f"{step.tool} did not write {output}")

    def xdelta(self, step: Step) -> None:
        """Apply an xdelta3 patch with the native ``xdelta3``.

        Args:
            step: The ``x.exe`` step.

        Raises:
            UnfitError: When the patch does not apply.
        """
        source, patch, output = (self.path(arg) for arg in xdelta_operands(step.args))
        command = [str(self._context.xdelta), "-f", "-d", "-s"]
        command += [str(source), str(patch), str(output)]
        run_tool(command, self._cwd, wine=False)

    def delete(self, targets: Sequence[str]) -> None:
        """Move deleted files aside; they are removed once the chain succeeds.

        Targets in the scripts folder never get here: :func:`parse_step` drops
        them so the scripts stay available for ``--finish``.

        Args:
            targets: Files to delete, as written in the script.
        """
        for target in targets:
            path = self.path(target)
            if not path.is_file():
                continue
            self._trash.mkdir(parents=True, exist_ok=True)
            self._deleted += 1
            parked = self._trash / f"{self._deleted}-{path.name}"
            while parked.exists():
                parked = parked.with_name(f"0{parked.name}")
            path.replace(parked)


@dataclasses.dataclass
class PostInstallTally:
    """How many chains ran and how many had nothing left to do."""

    ran: int = 0
    skipped: int = 0


class PlannedChain(NamedTuple):
    """A chain with its position in the batch and its working folder."""

    number: int
    chain: Chain
    cwd: Path


def plan_batch(
    context: PostInstallContext,
    batch: Batch,
    index: FileIndex,
    tally: PostInstallTally,
) -> tuple[list[PlannedChain], FileIndex]:
    """Find the working folder of every chain in a batch.

    The index is rebuilt when it cannot place a chain, since earlier chains
    may have created or removed files since it was built.

    Args:
        context: Destination and helper programs.
        batch: The batch to plan.
        index: Files under the destination, possibly stale.
        tally: Counts chains with nothing left to do.

    Returns:
        The runnable chains and the index to reuse for the next batch.

    Raises:
        UnfitError: When a chain fits several folders.
    """
    planned: list[PlannedChain] = []
    for number, chain in enumerate(batch.chains):
        folders = chain_folders(index, chain)
        usable = len(folders) == 1 and probes_exist(
            context.root / next(iter(folders)), chain
        )
        if not usable:
            index = FileIndex(context.root)
        folder = locate_chain(index, chain)
        if folder is None:
            tally.skipped += 1
            continue
        planned.append(PlannedChain(number, chain, context.root / folder))
    return planned, index


def execute_batch(
    context: PostInstallContext,
    batch: Batch,
    planned: Sequence[PlannedChain],
    tally: PostInstallTally,
    workers: int,
) -> None:
    """Run planned chains, in parallel when the batch came from a run list.

    Args:
        context: Destination and helper programs.
        batch: The batch the chains belong to.
        planned: Chains with their working folders.
        tally: Counts the chains that ran.
        workers: Parallel chains for run lists.

    Raises:
        UnfitError: From the first chain that fails; pending chains are cancelled.
    """
    trash_root = context.root / TRASH_DIR

    def execute(item: PlannedChain) -> None:
        """Run one planned chain with its own trash folder.

        Args:
            item: The chain and its working folder.
        """
        trash = trash_root / f"{batch.origin.replace(':', '-')}-{item.number}"
        ChainRunner(context, item.cwd, trash).run(item.chain)

    if not batch.parallel or len(planned) <= 1:
        for item in planned:
            execute(item)
            tally.ran += 1
    else:
        print(f"  {batch.origin}: {len(planned)} commands in parallel", flush=True)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(execute, item) for item in planned]
            try:
                for done, future in enumerate(as_completed(futures), 1):
                    future.result()
                    tally.ran += 1
                    if done % 25 == 0 or done == len(futures):
                        print(f"    {done}/{len(futures)}", flush=True)
            except BaseException:
                for future in futures:
                    future.cancel()
                raise
    if trash_root.is_dir() and not any(trash_root.iterdir()):
        trash_root.rmdir()


def run_batch(
    context: PostInstallContext,
    batch: Batch,
    index: FileIndex,
    tally: PostInstallTally,
    workers: int,
) -> FileIndex:
    """Plan and run one batch.

    Args:
        context: Destination and helper programs.
        batch: The batch to run.
        index: Files under the destination, possibly stale.
        tally: Counts chains that ran or were skipped.
        workers: Parallel chains for run lists.

    Returns:
        A file index that is fresh enough to reuse for the next batch.

    Raises:
        UnfitError: When a chain cannot be placed or fails.
    """
    planned, index = plan_batch(context, batch, index, tally)
    execute_batch(context, batch, planned, tally, workers)
    if batch.parallel and len(planned) > 1:
        index = FileIndex(context.root)
    return index


def print_tally(tally: PostInstallTally) -> None:
    """Print how many command chains ran and how many were skipped.

    Args:
        tally: Counts from one replay.
    """
    summary = f"post-install: {tally.ran} command chain(s) ran"
    if tally.skipped:
        summary += f", {tally.skipped} skipped (inputs gone, already applied?)"
    print(summary)


def run_post_install(
    dest: Path, wine: Path, *, setup: Path | None = None, workers: int | None = None
) -> int:
    """Replay the pack's ``build*.bat`` scripts, then the commands in ``setup.exe``.

    Args:
        dest: Unpacked folder.
        wine: Wine binary for helpers that only exist as Windows programs.
        setup: The pack's installer; None skips its commands.
        workers: Parallel chains for run lists; half the CPU threads by default.

    Returns:
        0 when there was nothing to do or everything ran, 1 on failure.

    Raises:
        UnfitError: When a tool the replay needs (``xdelta3``, ``innoextract``)
            is not installed.
    """
    code = replay_build_scripts(dest, wine, workers=workers)
    if code == 0 and setup is not None:
        code = replay_installer_commands(dest, wine, setup)
    return code


def replay_build_scripts(dest: Path, wine: Path, *, workers: int | None = None) -> int:
    """Replay FitGirl's ``build*.bat`` post-install scripts, if the pack has any.

    Every script is parsed before anything runs, so an unsupported command
    leaves the destination untouched.

    Args:
        dest: Unpacked folder.
        wine: Wine binary for helpers that only exist as Windows programs.
        workers: Parallel chains for run lists; half the CPU threads by default.

    Returns:
        0 when there was nothing to do or everything ran, 1 on failure.

    Raises:
        UnfitError: When the scripts need ``xdelta3`` and it is not installed.
    """
    try:
        found = find_post_install_scripts(dest)
        if found is None:
            return 0
        scripts_root, scripts = found
        markers = wait_markers(scripts)
        parsed = [
            (script, parse_post_install_script(script, scripts_root, markers))
            for script in scripts
        ]
    except UnfitError as error:
        LOGGER.error("post-install: not replayed, %s", error)
        return 1

    xdelta = shutil.which("xdelta3")
    needs_xdelta = any(
        step.tool == "x.exe"
        for _, batches in parsed
        for batch in batches
        for chain in batch.chains
        for step in chain.steps
    )
    if xdelta is None and needs_xdelta:
        rerun = shlex.join(["unfit", "--finish", str(dest)])
        raise UnfitError(
            "xdelta3 is missing; this pack's post-install scripts apply xdelta "
            f"patches. Install xdelta3, then run: {rerun}"
        )
    names = ", ".join(script.name for script in scripts)
    print(f"post-install: replaying {names} from {scripts_root.relative_to(dest)}")
    try:
        windows_root = windows_path(wine, dest)
    except UnfitError as error:
        LOGGER.error("post-install: not replayed, %s", error)
        return 1
    context = PostInstallContext(
        root=dest,
        scripts_root=scripts_root,
        wine=wine,
        xdelta=Path(xdelta or "xdelta3"),
        windows_root=windows_root,
    )
    tally = PostInstallTally()
    index = FileIndex(dest)
    try:
        for _, batches in parsed:
            for batch in batches:
                index = run_batch(
                    context,
                    batch,
                    index,
                    tally,
                    workers or max(1, (os.cpu_count() or 2) // 2),
                )
    except UnfitError as error:
        LOGGER.error("post-install: failed at %s", error)
        return 1
    print_tally(tally)
    return 0


# --- commands in the install script ------------------------------------------
#
# Some repacks rebuild files from the install script instead of a build*.bat:
# after unpacking volumes into FOLDER, its [Code] section runs
# Exec('{cmd}', '/C "{tmp}\x5.exe" ARGS', '{app}\FOLDER\', ...). The compiled
# script (PascalScript, "IFPS") sits in the setup header, an LZMA block in
# setup.exe, and stores string literals inline in program order, so such a
# command shows up as the literals FOLDER, "/C ", "{tmp}\TOOL", ARGS, "{cmd}".
# fitgirl-extractor unpacks every volume into the game root, so inputs are
# taken from FOLDER first and from the root second.

SETUP_LOADER_MAGIC = b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a"
SETUP_LOADER_FIELDS = struct.Struct("<8I")
SETUP_DATA_MAGIC = b"Inno Setup Setup Data ("
SETUP_ID_SIZE = 64
SETUP_BLOCK_HEADER = struct.Struct("<IIB")
SETUP_CHUNK_SIZE = 4096
SETUP_CHUNK_CRC = struct.Struct("<I")
LZMA_PROPS_SIZE = 5
IFPS_MAGIC = b"IFPS"
IFPS_CONSTANT = 0x01
IFPS_TMP_LITERAL = re.compile(rb"\{tmp\}\\", re.IGNORECASE)
MAX_LITERAL_SIZE = 1 << 16
CONTROL_BYTES = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")
INSTALLER_EXEC = re.compile(r"^\{tmp\}\\([^\\]+\.exe)$", re.IGNORECASE)
INSTALLER_WORKDIR = re.compile(r"^\{app\}(?:\\(.*?))?\\?$", re.IGNORECASE)


@dataclasses.dataclass(frozen=True)
class InstallerCommand:
    """One command the install script runs, with its working folder."""

    origin: str
    workdir: str
    chain: Chain


def decode_lzma1(payload: bytes) -> bytes:
    """Decompress Inno Setup's LZMA1 stream: 5 property bytes, then raw data.

    Args:
        payload: Properties byte, dictionary size and the compressed data.

    Returns:
        The decompressed bytes.

    Raises:
        UnfitError: When the properties are invalid or the data is corrupt.
    """
    if len(payload) < LZMA_PROPS_SIZE or payload[0] >= 9 * 5 * 5:
        raise UnfitError("setup header has invalid LZMA properties")
    props = payload[0]
    (dict_size,) = struct.unpack_from("<I", payload, 1)
    lzma_filter = {
        "id": lzma.FILTER_LZMA1,
        "lc": props % 9,
        "lp": props // 9 % 5,
        "pb": props // 45,
        "dict_size": dict_size,
    }
    decompressor = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[lzma_filter])
    try:
        return decompressor.decompress(payload[LZMA_PROPS_SIZE:])
    except lzma.LZMAError as error:
        raise UnfitError(f"setup header does not decompress: {error}") from error


def read_setup_header(setup: Path) -> bytes:
    """Read the setup header (settings, entries, compiled script) of ``setup.exe``.

    Args:
        setup: An Inno Setup 5.1.5+ installer.

    Returns:
        The decompressed header block.

    Raises:
        UnfitError: When the file is not such an installer or a checksum fails.
    """
    data = setup.read_bytes()
    table = data.find(SETUP_LOADER_MAGIC)
    fields_at = table + len(SETUP_LOADER_MAGIC)
    if table < 0 or len(data) < fields_at + SETUP_LOADER_FIELDS.size:
        raise UnfitError(f"{setup.name} has no Inno Setup loader table")
    fields = SETUP_LOADER_FIELDS.unpack_from(data, fields_at)
    version, offset0, table_crc = fields[0], fields[5], fields[7]
    if version != 1 or zlib.crc32(data[table : fields_at + 28]) != table_crc:
        raise UnfitError(f"{setup.name} has an unsupported Inno Setup loader table")
    if not data.startswith(SETUP_DATA_MAGIC, offset0):
        raise UnfitError(f"{setup.name} has no setup data where its loader points")
    position = offset0 + SETUP_ID_SIZE
    header_crc, stored_size, compressed = SETUP_BLOCK_HEADER.unpack_from(data, position)
    sizes = data[position + 4 : position + SETUP_BLOCK_HEADER.size]
    start = position + SETUP_BLOCK_HEADER.size
    block = data[start : start + stored_size]
    if zlib.crc32(sizes) != header_crc or len(block) != stored_size:
        raise UnfitError(f"{setup.name}: setup header is damaged")
    payload = bytearray()
    for offset in range(0, stored_size, SETUP_CHUNK_SIZE + SETUP_CHUNK_CRC.size):
        (chunk_crc,) = SETUP_CHUNK_CRC.unpack_from(block, offset)
        chunk_start = offset + SETUP_CHUNK_CRC.size
        chunk = block[chunk_start : chunk_start + SETUP_CHUNK_SIZE]
        if zlib.crc32(chunk) != chunk_crc:
            raise UnfitError(f"{setup.name}: setup header chunk fails its checksum")
        payload += chunk
    return decode_lzma1(bytes(payload)) if compressed else bytes(payload)


def literal_type(code: bytes) -> bytes | None:
    r"""Find the type id the compiled script uses for string literals.

    Args:
        code: The compiled script, from its ``IFPS`` magic on.

    Returns:
        The 4-byte type id of the ``{tmp}\...`` literals, or None when there
        are none.
    """
    types: Counter[bytes] = Counter()
    for match in IFPS_TMP_LITERAL.finditer(code):
        start = match.start() - 9
        if start >= 0 and code[start] == IFPS_CONSTANT:
            types[code[start + 1 : start + 5]] += 1
    return types.most_common(1)[0][0] if types else None


def installer_literals(header: bytes) -> list[str]:
    """Return the string literals of the compiled install script, in order.

    Args:
        header: The setup header from :func:`read_setup_header`.

    Returns:
        Literals that look like text; empty when the header has no script.
    """
    start = header.find(IFPS_MAGIC)
    if start < 0:
        return []
    code = header[start:]
    string_type = literal_type(code)
    if string_type is None:
        return []
    pattern = re.compile(
        re.escape(bytes([IFPS_CONSTANT]) + string_type) + rb"(.{4})", re.DOTALL
    )
    literals: list[str] = []
    position = 0
    while match := pattern.search(code, position):
        (length,) = struct.unpack("<I", match.group(1))
        body = code[match.end() : match.end() + length]
        is_text = len(body) == length and not CONTROL_BYTES.search(body)
        if 0 < length <= MAX_LITERAL_SIZE and is_text:
            literals.append(body.decode("cp1252", errors="replace"))
            position = match.end() + length
        else:
            position = match.start() + 1
    return literals


def parse_installer_command(
    literals: Sequence[str], index: int, origin: str
) -> InstallerCommand:
    r"""Turn the literals around ``{tmp}\TOOL`` into a command chain.

    Args:
        literals: All literals of the script.
        index: Position of the ``{tmp}\TOOL`` literal.
        origin: Label for messages.

    Returns:
        The command with its working folder relative to the game folder.

    Raises:
        UnfitError: When the literals do not have the expected shape, or the
            arguments use anything but the tool and ``del``.
    """
    tool = PureWindowsPath(literals[index]).name.lower()
    window = literals[index - 2 : index + 3]
    if index < 2 or len(window) != 5 or window[4].lower() != "{cmd}":
        raise UnfitError(f"{origin}: {tool} is not run in the expected way")
    folder = INSTALLER_WORKDIR.match(window[0])
    if folder is None:
        raise UnfitError(f"{origin}: {tool} runs outside the game folder: {window[0]}")
    workdir = folder.group(1) or ""
    text = f"{tool} {window[3]}"
    try:
        if workdir:
            check_script_path(workdir)
        if "{" in window[3]:
            raise UnfitError("Inno Setup constants in arguments are not supported")
        parts = split_and_chain(text)
        step = Step(tool, tuple(split_cmd_words(parts[0])[1:]))
        files = step_files(step)
        for operand in (*files.inputs, *files.outputs):
            check_script_path(operand)
    except UnfitError as error:
        raise UnfitError(f"{origin}: {error}: {text}") from error
    rest = [parse_step(part, origin) for part in parts[1:]]
    if any(item.tool != "del" for item in rest):
        raise UnfitError(f"{origin}: only del may follow {tool}: {text}")
    steps = (step, *(item for item in rest if item.args))
    return InstallerCommand(origin, workdir, Chain(origin, steps))


def parse_installer_commands(
    literals: Sequence[str],
) -> tuple[list[InstallerCommand], list[str]]:
    r"""Find the ``cmd /C "{tmp}\TOOL" ...`` commands of an install script.

    Args:
        literals: String literals from :func:`installer_literals`.

    Returns:
        The commands unfit can replay, and the names of other tools the
        script runs that way in the game folder (tools that only work on the
        installer's temp files, such as an ``arc.ini`` rewrite, are left out).

    Raises:
        UnfitError: When a known tool is called in a way unfit cannot replay.
    """
    commands: list[InstallerCommand] = []
    others: list[str] = []
    for index, literal in enumerate(literals):
        match = INSTALLER_EXEC.match(literal)
        if not match or index == 0 or literals[index - 1].strip().lower() != "/c":
            continue
        tool = match.group(1).lower()
        if tool not in INSTALLER_TOOLS:
            in_game = index >= 2 and INSTALLER_WORKDIR.match(literals[index - 2])
            if in_game and tool not in others:
                others.append(tool)
            continue
        origin = f"setup.exe command {len(commands) + 1}"
        commands.append(parse_installer_command(literals, index, origin))
    return commands, others


def place_installer_inputs(root: Path, command: InstallerCommand) -> Path | None:
    """Gather a command's inputs in its working folder.

    Inputs the extractor left in the game root are moved into the working
    folder, where the installer would have unpacked them.

    Args:
        root: Unpacked folder.
        command: The command to place.

    Returns:
        The working folder, or None when an input is missing (the command
        already ran, or its optional volume was not unpacked).
    """
    workdir = resolve_case_insensitive(root, command.workdir)
    moves: list[Move] = []
    missing: list[str] = []
    for probe in chain_probes(command.chain):
        if resolve_case_insensitive(workdir, probe).is_file():
            continue
        stray = resolve_case_insensitive(root, probe)
        if stray.is_file():
            moves.append(Move(stray, resolve_case_insensitive(workdir, probe)))
        else:
            missing.append(probe)
    if missing:
        if moves:
            LOGGER.warning(
                "%s: skipped, %s missing; left %s in place",
                command.origin,
                ", ".join(missing),
                ", ".join(move.source.name for move in moves),
            )
        return None
    if moves:
        apply_moves(moves)
        names = ", ".join(move.source.name for move in moves)
        print(f"  moved {names} into {command.workdir or '.'}")
    return workdir


def unpack_installer_tools(
    innoextract: str, setup: Path, staging: Path, names: Sequence[str]
) -> Path:
    """Unpack the helper programs the install script runs from ``{tmp}``.

    Args:
        innoextract: The ``innoextract`` binary.
        setup: The pack's installer.
        staging: Empty folder inside the destination to unpack into.
        names: Program names, e.g. ``x5.exe``.

    Returns:
        The folder holding the programs.

    Raises:
        UnfitError: When the staging folder cannot be cleared or a program is
            not in the installer.
    """
    if not remove_tree(staging):
        raise UnfitError(f"cannot clear {staging}")
    command = [innoextract, "--extract", "--silent", "--output-dir", str(staging)]
    for name in names:
        command += ["--include", f"tmp/{name}"]
    run_tool([*command, str(setup)], setup.parent, wine=False)
    folder = staging / "tmp"
    for name in names:
        if not resolve_case_insensitive(folder, name).is_file():
            raise UnfitError(f"innoextract did not unpack {name} from {setup.name}")
    return folder


def has_pending_input(root: Path, commands: Sequence[InstallerCommand]) -> bool:
    """Return True when an unpacked input still exists, so replay has work to do.

    Inputs that an earlier command creates (e.g. the archive a later command
    patches in place) do not count: they stay after a finished replay.

    Args:
        root: Unpacked folder.
        commands: Commands from the install script.

    Returns:
        True when such an input is in its working folder or in the root.
    """
    produced: set[str] = set()
    for command in commands:
        folder = PureWindowsPath(command.workdir)
        workdir = resolve_case_insensitive(root, command.workdir)
        for probe in chain_probes(command.chain):
            if (folder / probe).as_posix().lower() in produced:
                continue
            for base in (workdir, root):
                if resolve_case_insensitive(base, probe).is_file():
                    return True
        produced.update(
            (folder / output).as_posix().lower()
            for step in command.chain.steps
            for output in step_files(step).outputs
        )
    return False


def read_installer_commands(setup: Path) -> list[InstallerCommand] | None:
    """Read the replayable commands of an install script.

    Args:
        setup: The pack's installer.

    Returns:
        The commands, or None when the header cannot be read (logged).

    Raises:
        UnfitError: When a known tool is called in a way unfit cannot replay.
    """
    try:
        header = read_setup_header(setup)
    except (UnfitError, OSError) as error:
        LOGGER.warning("install script commands not checked: %s", error)
        return None
    commands, others = parse_installer_commands(installer_literals(header))
    for tool in others:
        LOGGER.warning("%s also runs %s, which unfit does not replay", setup.name, tool)
    return commands


def replay_installer_commands(dest: Path, wine: Path, setup: Path) -> int:
    """Replay the helper commands the install script runs after unpacking.

    Args:
        dest: Unpacked folder.
        wine: Wine binary for the helpers.
        setup: The pack's installer.

    Returns:
        0 when there was nothing to do or everything ran, 1 on failure.

    Raises:
        UnfitError: When commands are pending and ``innoextract`` is missing.
    """
    try:
        commands = read_installer_commands(setup)
    except UnfitError as error:
        LOGGER.error("post-install: not replayed, %s", error)
        return 1
    if not commands:
        return 0
    if not has_pending_input(dest, commands):
        print_tally(PostInstallTally(skipped=len(commands)))
        return 0
    innoextract = shutil.which("innoextract")
    if innoextract is None:
        rerun = shlex.join(["unfit", "--finish", str(setup.parent), "-d", str(dest)])
        raise UnfitError(
            f"innoextract is missing; {setup.name} rebuilds files with helpers it "
            f"carries. Install innoextract, then run: {rerun}"
        )
    print(f"post-install: replaying {len(commands)} command(s) from {setup.name}")
    names = sorted(
        {
            step.tool
            for command in commands
            for step in command.chain.steps
            if step.tool in INSTALLER_TOOLS
        }
    )
    staging = dest / TOOL_STAGING_DIR
    trash_root = dest / TRASH_DIR
    tally = PostInstallTally()
    try:
        context = PostInstallContext(
            root=dest,
            scripts_root=dest,
            wine=wine,
            xdelta=Path("xdelta3"),
            windows_root=windows_path(wine, dest),
            installer_tools=unpack_installer_tools(innoextract, setup, staging, names),
        )
        for command in commands:
            workdir = place_installer_inputs(dest, command)
            if workdir is None:
                tally.skipped += 1
                continue
            print(f"  {command.origin}: {command.chain.steps[0].tool}", flush=True)
            trash = trash_root / command.origin.replace(" ", "-")
            ChainRunner(context, workdir, trash).run(command.chain)
            tally.ran += 1
    except (UnfitError, OSError) as error:
        LOGGER.error("post-install: failed at %s", error)
        return 1
    finally:
        remove_tree(staging)
        if trash_root.is_dir() and not any(trash_root.iterdir()):
            trash_root.rmdir()
    print_tally(tally)
    return 0


def check_destination(pack_dir: Path, dest: Path, *, overwrite: bool) -> None:
    """Reject a destination inside the pack and a folder that already has files.

    Args:
        pack_dir: The repack folder.
        dest: Destination folder.
        overwrite: Allow a non-empty destination.

    Raises:
        UnfitError: When the destination is inside the pack or not empty.
    """
    if dest == pack_dir or pack_dir in dest.parents:
        raise UnfitError(f"destination is inside the pack: {dest}")
    confirm_overwrite(dest, overwrite=overwrite)


def confirm_overwrite(dest: Path, *, overwrite: bool) -> None:
    """Refuse to unpack into a folder that already holds files.

    Args:
        dest: Destination folder.
        overwrite: Allow a non-empty destination.

    Raises:
        UnfitError: When the folder has files and ``overwrite`` is False.
    """
    if overwrite or not dest.exists():
        return
    if any(dest.iterdir()):
        raise UnfitError(f"destination is not empty: {dest} (use --overwrite)")


def log_path_for(pack: PackFiles) -> Path:
    """Build a timestamped log file path for this run.

    Args:
        pack: The repack.

    Returns:
        A path under the state folder's ``logs``.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return STATE_DIR / "logs" / f"{stamp}-{derive_dest_name(pack.pack_dir)[:40]}.log"


def run_check(pack: PackFiles, bar: ProgressBar) -> int:
    """Verify the ``.bin`` volumes and report the result.

    Args:
        pack: The repack.
        bar: Progress renderer for hashing.

    Returns:
        0 when every required volume matched, 1 otherwise.
    """
    report = verify_bins(pack, bar)
    print(f"bins: {describe_report(report, selective_missing=True)}")
    return 1 if report.bad or required_missing(report) else 0


def run_list(
    pack: PackFiles, tools: Toolchain, log_path: Path, *, verbose: bool, echo: bool
) -> int:
    """Ask the extractor for the archive listing.

    Args:
        pack: The repack.
        tools: Wine and the extractor.
        log_path: Run log.
        verbose: Ask the extractor for per-file detail.
        echo: Show the listing.

    Returns:
        The extractor's exit code.
    """
    flags = ExtractFlags(list_only=True, verbose=verbose)
    command = build_extract_command(tools, pack.pack_dir, None, flags)
    return run_streaming(command, log_path, echo=echo)


# --- installer tools shipped in a volume --------------------------------------
#
# Some packs ship an external decompressor in a volume of its own, e.g. a
# small volume with tools\xtool.exe, and arc.ini runs it by that relative
# path. The real installer unpacks that volume into its temp folder first.
# fitgirl-extractor unpacks every volume into the game folder instead and runs
# unarc.dll from a temp folder it recreates per run, so the volume that needs
# the tool fails with "archive data corrupted (decompression fails)". Wine
# looks up relative program names in the folder of the running .exe first, so
# a copy of the extractor next to the tool folders can find them.

EXTRACTOR_ARC_INI = PurePosixPath(".fgtmp/setup/tmp/arc.ini")
TOOL_STAGING_DIR = ".unfit-tools"
ARC_POLL_INTERVAL = 0.2
FAILED_VOLUME = re.compile(r"^WARNING: (\S.*?\.bin) failed\b", re.IGNORECASE)
UNPACK_COMMAND = re.compile(
    r'^\s*unpackcmd\s*=\s*("[^"]+"|\S+)', re.IGNORECASE | re.MULTILINE
)


class ArcIniCatcher:
    """Copy arc.ini out of the extractor's work folder while it exists.

    fitgirl-extractor deletes its work folder when it exits, and arc.ini is
    the only place that says which external tools the archives need.
    """

    def __init__(self, dest: Path) -> None:
        """Watch ``dest`` for the extractor's arc.ini."""
        self._path = dest / EXTRACTOR_ARC_INI
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._previous: str | None = None
        self.text: str | None = None

    def __enter__(self) -> ArcIniCatcher:
        """Start watching."""
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        """Stop watching."""
        self._stop.set()
        self._thread.join(timeout=ARC_POLL_INTERVAL * 5)

    def _poll(self) -> None:
        while not self._stop.wait(ARC_POLL_INTERVAL):
            if self._grab():
                return

    def _grab(self) -> bool:
        """Keep the file once two reads in a row agree (it is fully written)."""
        try:
            text = self._path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            self._previous = None
            return False
        if text and text == self._previous:
            self.text = text
            return True
        self._previous = text
        return False


def collect_failed_volume(line: str, failed: list[str]) -> None:
    """Record volumes the extractor reports as failed.

    Args:
        line: One line of extractor output.
        failed: Receives each failed volume once.
    """
    match = FAILED_VOLUME.match(line.strip())
    if match and match.group(1) not in failed:
        failed.append(match.group(1))


def parse_arc_tool_dirs(text: str) -> set[str]:
    r"""Folders that arc.ini runs external tools from (``tools\xtool.exe``).

    Args:
        text: Content of ``arc.ini``.

    Returns:
        First path components of relative ``unpackcmd`` programs.
    """
    folders: set[str] = set()
    for match in UNPACK_COMMAND.finditer(text):
        program = PureWindowsPath(match.group(1).strip('"'))
        parts = program.parts
        if program.drive or program.root or len(parts) < 2 or ".." in parts:
            continue
        folders.add(parts[0])
    return folders


def find_tool_dirs(dest: Path, names: set[str]) -> list[Path]:
    """Unpacked top-level folders that arc.ini uses as tool folders.

    A folder that ``_Redist/fitgirl.md5`` lists files in belongs to the game
    and is never treated as a tool folder.

    Args:
        dest: Unpacked folder.
        names: Folder names from :func:`parse_arc_tool_dirs`.

    Returns:
        Matching folders, sorted.
    """
    wanted = {name.lower() for name in names}
    if not wanted or not dest.is_dir():
        return []
    manifest = destination_manifest(dest) or {}
    owned = {PurePosixPath(path).parts[0].lower() for path in manifest}
    return sorted(
        entry
        for entry in dest.iterdir()
        if entry.is_dir()
        and entry.name.lower() in wanted
        and entry.name.lower() not in owned
    )


def remove_tool_dirs(dest: Path, tool_dirs: Sequence[Path]) -> None:
    """Delete installer tool folders from the game folder.

    Only done when ``_Redist/fitgirl.md5`` exists, since that is what shows
    the folders are not part of the game.

    Args:
        dest: Unpacked folder.
        tool_dirs: Folders from :func:`find_tool_dirs`.
    """
    if not tool_dirs or destination_manifest(dest) is None:
        return
    removed = [folder for folder in tool_dirs if remove_tree(folder)]
    if removed:
        names = ", ".join(f"{folder.name}\\" for folder in removed)
        print(f"removed installer tools {names} from the game folder")


@dataclasses.dataclass(frozen=True)
class ExtractSession:
    """Everything one extraction run needs once the unpacked size is known."""

    pack: PackFiles
    tools: Toolchain
    options: RunOptions
    progress: ProgressTarget

    def unpack(self, extractor: Path, only: tuple[str, ...], failed: list[str]) -> int:
        """Run the extractor on the selected volumes (all when ``only`` is empty).

        Args:
            extractor: The ``fitgirl-extractor.exe`` to run.
            only: Volumes to unpack.
            failed: Receives the volumes the extractor reports as failed.

        Returns:
            The extractor's exit code.
        """
        flags = ExtractFlags(
            skip_bin_check=True,
            skip_verify=True,
            verbose=self.options.verbose,
            only=only,
        )
        tools = dataclasses.replace(self.tools, extractor=extractor)
        command = build_extract_command(
            tools, self.pack.pack_dir, self.options.dest, flags
        )
        return run_streaming(
            command,
            self.options.log_path,
            progress=self.progress,
            echo=self.options.echo,
            on_line=functools.partial(collect_failed_volume, failed=failed),
        )


def retry_with_tools(
    session: ExtractSession, failed: Sequence[str], tool_dirs: Sequence[Path]
) -> int:
    """Unpack failed volumes again, with the tool folders next to the extractor.

    Args:
        session: The extraction run.
        failed: Volumes that failed the first time.
        tool_dirs: Unpacked tool folders that arc.ini runs programs from.

    Returns:
        0 when every retried volume unpacked, 1 otherwise.

    Raises:
        UnfitError: When the staging folder cannot be prepared.
    """
    staging = session.options.dest / TOOL_STAGING_DIR
    if not remove_tree(staging):
        raise UnfitError(f"cannot clear {staging} for the retry")
    staging.mkdir()
    names = ", ".join(f"{folder.name}\\" for folder in tool_dirs)
    still_failed: list[str] = []
    try:
        extractor = staging / session.tools.extractor.name
        shutil.copy2(session.tools.extractor, extractor)
        for folder in tool_dirs:
            shutil.copytree(folder, staging / folder.name)
        for volume in failed:
            print(f"retrying {volume} with the installer tools {names}")
            again: list[str] = []
            code = session.unpack(extractor, (volume,), again)
            if code != 0 or again:
                still_failed.append(volume)
    finally:
        remove_tree(staging)
    if still_failed:
        LOGGER.error(
            "still failing with the installer tools: %s", ", ".join(still_failed)
        )
        return 1
    return 0


def check_volumes(pack: PackFiles, bar: ProgressBar) -> None:
    """Verify the ``.bin`` volumes before unpacking.

    Args:
        pack: The repack.
        bar: Progress renderer for hashing.

    Raises:
        UnfitError: When a volume is damaged or a required one is missing.
    """
    report = verify_bins(pack, bar)
    print(f"bins: {describe_report(report, selective_missing=True)}")
    if report.bad:
        raise UnfitError(
            "volume checksum mismatch - delete and re-download those files"
        )
    missing = required_missing(report)
    if missing:
        raise UnfitError(f"missing volumes: {', '.join(missing)}")


def measure_unpacked_size(pack: PackFiles, tools: Toolchain, log_path: Path) -> int:
    """Ask the extractor how many bytes the volumes unpack to.

    Args:
        pack: The repack.
        tools: Wine and the extractor.
        log_path: Run log.

    Returns:
        The unpacked size in bytes.

    Raises:
        UnfitError: When the listing fails or reports nothing.
    """
    listing: list[str] = []
    command = build_extract_command(
        tools, pack.pack_dir, None, ExtractFlags(list_only=True)
    )
    code = run_streaming(command, log_path, echo=False, on_line=listing.append)
    total = parse_unpacked_bytes("".join(listing))
    if code != 0 or total <= 0:
        raise UnfitError(
            "cannot read the archive listing; run `unfit --list` to see why"
        )
    return total


def ensure_free_space(dest: Path, total: int) -> None:
    """Create the destination and check it can hold the unpacked volumes.

    Args:
        dest: Destination folder.
        total: Unpacked size in bytes.

    Raises:
        UnfitError: When the disk is too full.
    """
    dest.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(dest).free
    needed = total + SPACE_MARGIN
    if free < needed:
        raise UnfitError(
            f"not enough space on {dest}: "
            f"need {needed / 1024**3:.1f} GiB, have {free / 1024**3:.1f} GiB"
        )


def unpack_volumes(session: ExtractSession) -> int:
    """Unpack every volume, retrying those that need tools from another volume.

    Args:
        session: The extraction run.

    Returns:
        0 when every volume unpacked, otherwise the failing exit code.
    """
    dest = session.options.dest
    failed: list[str] = []
    with ArcIniCatcher(dest) as catcher:
        code = session.unpack(session.tools.extractor, (), failed)
    tool_dirs = (
        find_tool_dirs(dest, parse_arc_tool_dirs(catcher.text)) if catcher.text else []
    )
    if failed and tool_dirs:
        code = retry_with_tools(session, failed, tool_dirs)
    elif failed:
        LOGGER.warning(
            "no installer tool folders from arc.ini were unpacked, "
            "so the failed volume(s) were not retried"
        )
    if code == 0:
        remove_tool_dirs(dest, tool_dirs)
    else:
        LOGGER.error("extractor exited with code %s", code)
    return code


@dataclasses.dataclass(frozen=True)
class FinishSteps:
    """Which finishing steps to run on an unpacked folder."""

    setup: Path | None
    post_install: bool
    verify: bool


def finish_destination(
    dest: Path, wine: Path, bar: ProgressBar, steps: FinishSteps
) -> int:
    """Repair the layout, replay post-install steps and verify.

    Args:
        dest: Unpacked folder.
        wine: Wine binary for post-install helpers.
        bar: Progress renderer for hashing.
        steps: The installer whose commands to replay (None: only
            ``build*.bat``), whether to replay at all, and whether to check
            against ``_Redist/fitgirl.md5``.

    Returns:
        0 when every enabled step succeeded, 1 otherwise.
    """
    post_code = 0
    if steps.post_install:
        repair_layout(dest)
        post_code = run_post_install(dest, wine, setup=steps.setup)
    verify_code = post_extract_verify(dest, bar) if steps.verify else 0
    print(
        "note: _Redist installers, registry entries, shortcuts and install-script "
        "renames are not applied - run the redistributables if the game needs them"
    )
    return 0 if post_code == 0 and verify_code == 0 else 1


def run_extract(
    pack: PackFiles, tools: Toolchain, options: RunOptions, bar: ProgressBar
) -> int:
    """Run the full extract flow: verify bins, check space, unpack, finish.

    Args:
        pack: The repack.
        tools: Wine and the extractor.
        options: Settings for this run.
        bar: Progress renderer.

    Returns:
        0 when everything unpacked and verified, 1 otherwise.

    Raises:
        UnfitError: When the volumes, listing or free space rule out unpacking.
    """
    if not options.skip_md5:
        check_volumes(pack, bar)
    total = measure_unpacked_size(pack, tools, options.log_path)
    ensure_free_space(options.dest, total)
    print(
        f"unpacking {len(pack.bins)} volume(s), {total / 1024**3:.2f} GiB "
        f"into {options.dest}"
    )
    session = ExtractSession(
        pack, tools, options, ProgressTarget(bar, options.dest, total)
    )
    code = unpack_volumes(session)
    finish_code = finish_destination(
        options.dest,
        tools.wine,
        bar,
        FinishSteps(
            setup=pack.setup,
            post_install=code == 0 and not options.skip_post_install,
            verify=not options.skip_verify,
        ),
    )
    return 0 if code == 0 and finish_code == 0 else 1


def run_finish(
    dest: Path, wine: Path, bar: ProgressBar, *, setup: Path | None, skip_verify: bool
) -> int:
    """Replay post-install steps on an already unpacked folder, then verify.

    Args:
        dest: Unpacked folder.
        wine: Wine binary for post-install helpers.
        bar: Progress renderer for hashing.
        setup: The pack's installer, to replay its commands; None skips them.
        skip_verify: Skip the check against ``_Redist/fitgirl.md5``.

    Returns:
        0 when everything succeeded, 1 otherwise.

    Raises:
        UnfitError: When ``dest`` is not a folder.
    """
    if not dest.is_dir():
        raise UnfitError(f"not a directory: {dest}")
    code = finish_destination(
        dest,
        wine,
        bar,
        FinishSteps(setup=setup, post_install=True, verify=not skip_verify),
    )
    if code != 0 and setup is None:
        print(
            "note: commands in the pack's setup.exe were not checked; to replay "
            "them too, run: unfit --finish PACK_DIR -d DIR"
        )
    return code


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Arguments without the program name; None reads ``sys.argv``.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog="unfit",
        description="Verify and unpack FitGirl repacks on Linux and macOS (via Wine).",
    )
    parser.add_argument(
        "pack_dir",
        type=Path,
        help=(
            "folder with setup.exe and fg-*.bin "
            "(with --finish and no -d: the unpacked folder)"
        ),
    )
    parser.add_argument(
        "-d", "--dest", type=Path, help="where to unpack (default: ~/Games/<name>)"
    )
    parser.add_argument(
        "--check", action="store_true", help="only verify the .bin volumes"
    )
    parser.add_argument(
        "--list", action="store_true", help="only list archive contents"
    )
    parser.add_argument(
        "--skip-md5", action="store_true", help="do not verify the .bin volumes"
    )
    parser.add_argument(
        "--skip-verify", action="store_true", help="skip the post-extract check"
    )
    parser.add_argument(
        "--no-post-install",
        action="store_true",
        help=(
            "do not replay the pack's work\\build*.bat scripts or the commands "
            "in its setup.exe"
        ),
    )
    parser.add_argument(
        "--finish",
        action="store_true",
        help=(
            "replay post-install steps on an already unpacked folder, then verify; "
            "PACK_DIR -d DIR also replays the commands in setup.exe"
        ),
    )
    parser.add_argument(
        "--overwrite", action="store_true", help="allow a non-empty destination"
    )
    parser.add_argument("--extractor", type=Path, help="path to fitgirl-extractor.exe")
    parser.add_argument("--wine", type=Path, help="path to a wine binary")
    parser.add_argument(
        "--no-progress", action="store_true", help="disable progress rendering"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="echo extractor detail"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="hide extractor output"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print commands, do nothing"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"unfit {UNFIT_VERSION} (fitgirl-extractor {EXTRACTOR_VERSION})",
    )
    return parser.parse_args(argv)


def configure_logging() -> None:
    """Send diagnostics to stderr; the run log is written by run_streaming."""
    logging.basicConfig(
        level=logging.INFO, format="unfit: %(message)s", stream=sys.stderr, force=True
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Arguments without the program name; None reads ``sys.argv``.

    Returns:
        Process exit code: 0 success, 1 verification or extraction failure,
        2 environment or usage error, 130 interrupted.
    """
    configure_logging()
    args = parse_args(argv)
    bar = ProgressBar(enabled=not args.no_progress and sys.stderr.isatty())

    try:
        if args.finish:
            source = args.pack_dir.expanduser().resolve()
            if args.dest is None:
                finish_dir, setup = source, None
            else:
                finish_dir, setup = args.dest.expanduser().resolve(), find_setup(source)
            return run_finish(
                finish_dir,
                detect_wine(args.wine),
                bar,
                setup=setup,
                skip_verify=args.skip_verify,
            )
        pack = find_pack_files(args.pack_dir.expanduser().resolve())
        if args.check:
            return run_check(pack, bar)

        tools = Toolchain(detect_wine(args.wine), ensure_extractor(args.extractor))
        log_path = log_path_for(pack)
        if args.list:
            return run_list(
                pack, tools, log_path, verbose=args.verbose, echo=not args.quiet
            )

        dest = (
            (args.dest or (Path.home() / "Games" / derive_dest_name(pack.pack_dir)))
            .expanduser()
            .resolve()
        )
        check_windows_ansi(pack.pack_dir)
        check_windows_ansi(dest)

        if args.dry_run:
            command = build_extract_command(
                tools,
                pack.pack_dir,
                dest,
                ExtractFlags(skip_bin_check=True, skip_verify=True),
            )
            print(
                f"would verify {len(pack.bins)} volume(s) against {pack.bins_manifest}"
            )
            print(f"would run: {shlex.join(command)}")
            if dest.exists() and any(dest.iterdir()):
                print("note: destination is not empty, a real run needs --overwrite")
            return 0

        check_destination(pack.pack_dir, dest, overwrite=args.overwrite)

        return run_extract(
            pack,
            tools,
            RunOptions(
                dest=dest,
                log_path=log_path,
                skip_md5=args.skip_md5,
                skip_verify=args.skip_verify,
                skip_post_install=args.no_post_install,
                verbose=args.verbose,
                echo=not args.quiet,
            ),
            bar,
        )
    except (UnfitError, OSError) as error:
        LOGGER.error("%s", error)
        return 2
    except KeyboardInterrupt:
        LOGGER.error("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
