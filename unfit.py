#!/usr/bin/env python3
"""unfit - verify and unpack FitGirl repacks on Linux.

FitGirl ``.bin`` volumes are produced by FitGirl's own modified FreeArc
(``unarc.dll`` shipped inside ``setup.exe``), so stock ``unarc`` cannot read
them.  This script drives ``fitgirl-extractor.exe`` (which calls that DLL under
Wine), and adds the checks that matter on Linux: hash verification of the
``.bin`` volumes, path and disk-space validation, a persistent Wine prefix, and
a post-extraction pass that repairs files the installer would have moved.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import contextlib
import dataclasses
import functools
import hashlib
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import NamedTuple, TextIO

UNFIT_VERSION = "0.1.0"
EXTRACTOR_VERSION = "0.2.1"
EXTRACTOR_SHA256 = "d4dbe676ee1b9eb23b9dc416ec69654da717c59aa89cb125557b11af59d98054"
EXTRACTOR_URL = (
    "https://github.com/pisek/fitgirl-extractor/releases/download/"
    f"v{EXTRACTOR_VERSION}/fitgirl-extractor.exe"
)

DATA_DIR = Path(os.environ.get("UNFIT_DATA_DIR", "~/.local/share/unfit")).expanduser()
STATE_DIR = Path(os.environ.get("UNFIT_STATE_DIR", "~/.local/state/unfit")).expanduser()
PREFIX_DIR = DATA_DIR / "wineprefix"
EXTRACTOR_PATH = DATA_DIR / "fitgirl-extractor.exe"

CHUNK_SIZE = 8 << 20
SPACE_MARGIN = 1 << 30
PROGRESS_INTERVAL = 1.5

SELECTIVE_PREFIX = "fg-selective"
MANIFEST_TAG = re.compile(r"\s*\[[^\]]*\]\s*$")
LIST_TOTAL = re.compile(r"(\d+) files?, (\d+) MB unpacked", re.IGNORECASE)
MANIFEST_DIGEST = re.compile(r"[0-9a-fA-F]{32}")


class UnfitError(Exception):
    """Raised for problems unfit can explain better than a traceback."""


@dataclasses.dataclass(frozen=True)
class PackFiles:
    """Files that make up one FitGirl repack."""

    pack_dir: Path
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
        """Return True when every manifest entry matched."""
        return not self.bad and not self.missing


class ProgressBar:
    """Single-line progress renderer that can be cleared for log lines."""

    def __init__(self, enabled: bool, stream: TextIO | None = None) -> None:
        """Create a bar; ``enabled=False`` makes every call a no-op."""
        self._enabled = enabled
        self._stream = stream if stream is not None else sys.stderr
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """Return True when this bar renders anything."""
        return self._enabled

    def render(self, done: int, total: int, label: str, start: float) -> None:
        """Draw one progress line for a transfer in progress."""
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
    """Return True when a manifest path stays inside the extraction root."""
    path = PurePosixPath(relative_path)
    return not path.is_absolute() and not any(part == ".." for part in path.parts)


def parse_md5_manifest(text: str) -> dict[str, str]:
    """Parse a FitGirl ``*.md5`` manifest into ``relative path -> digest``.

    Entries that would escape the extraction root are dropped: the manifest
    comes from the downloaded pack and is not trusted with paths outside it.

    Args:
        text: Manifest content, with lines like ``<md5> *..\\fg-01.bin``.

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
    """Read and parse a manifest file, tolerating non-UTF-8 bytes."""
    return parse_md5_manifest(path.read_text(encoding="utf-8", errors="replace"))


def derive_dest_name(pack_dir: Path) -> str:
    """Derive a destination folder name from the repack folder name.

    Trailing bracketed tags such as ``[FitGirl Repack]`` are dropped.
    """
    name = MANIFEST_TAG.sub("", pack_dir.name).strip(" -_")
    return name or pack_dir.name


def parse_unpacked_bytes(listing: str) -> int:
    """Sum the unpacked sizes reported by ``fitgirl-extractor --list``.

    The tool prints one ``N files, X MB unpacked, Y MB packed`` line per
    volume, and reports MiB under an ``MB`` label.
    """
    return sum(
        int(match.group(2)) * 1024 * 1024 for match in LIST_TOTAL.finditer(listing)
    )


def find_pack_files(pack_dir: Path) -> PackFiles:
    """Locate ``setup.exe``, the ``fg-*.bin`` volumes and the MD5 manifest.

    Raises:
        UnfitError: If the folder is not a recognisable FitGirl repack.
    """
    if not pack_dir.is_dir():
        raise UnfitError(f"not a directory: {pack_dir}")

    setup_candidates = [
        entry for entry in pack_dir.iterdir() if entry.name.lower() == "setup.exe"
    ]
    if not setup_candidates:
        raise UnfitError(f"no setup.exe in {pack_dir} - is this a FitGirl repack?")
    bins = tuple(sorted(path for path in pack_dir.glob("fg-*.bin") if path.is_file()))
    if not bins:
        raise UnfitError(f"no fg-*.bin volumes in {pack_dir}")
    manifests = sorted((pack_dir / "MD5").glob("*.md5"))
    if not manifests:
        raise UnfitError(f"no MD5/*.md5 manifest in {pack_dir}")
    return PackFiles(pack_dir, bins, manifests[0])


def is_selective(relative_path: str) -> bool:
    """Return True for optional selective-download volumes."""
    return PurePosixPath(relative_path).name.lower().startswith(SELECTIVE_PREFIX)


def hash_file(path: Path, bar: ProgressBar | None = None) -> str:
    """Return the MD5 hex digest of ``path``, optionally rendering progress."""
    total = path.stat().st_size
    digest = hashlib.md5()
    done = 0
    start = time.monotonic()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
            done += len(chunk)
            if bar is not None:
                bar.render(done, total, path.name, start)
    if bar is not None:
        bar.clear()
    return digest.hexdigest()


def verify_against_manifest(
    root: Path,
    manifest: Mapping[str, str],
    bar: ProgressBar | None = None,
) -> VerifyReport:
    """Hash every manifest entry under ``root`` and classify the results."""
    report = VerifyReport(total=len(manifest))
    for relative, expected in sorted(manifest.items()):
        candidate = root / relative
        if not candidate.is_file():
            report.missing.append(relative)
            continue
        actual = hash_file(candidate, bar)
        if actual == expected:
            report.ok.append(relative)
        else:
            report.bad.append(BadFile(relative, expected, actual))
    return report


def describe_report(report: VerifyReport, *, selective_missing: bool = False) -> str:
    """Render a one-line verification summary."""
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
    """Create parent folders and move each file into place."""
    for move in moves:
        move.target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(move.source), str(move.target))


def directory_size(root: Path, exclude: str = ".fgtmp") -> int:
    """Total bytes of regular files under ``root``, skipping ``exclude``."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name != exclude]
        for filename in filenames:
            with contextlib.suppress(OSError):
                total += os.stat(os.path.join(dirpath, filename)).st_size
    return total


def check_windows_ansi(path: Path) -> None:
    """Reject paths that ``unarc.dll`` cannot represent in the ANSI code page."""
    try:
        str(path).encode("cp1252")
    except UnicodeEncodeError as error:
        raise UnfitError(
            "path is not representable in Windows-1252, unarc.dll cannot use it: "
            f"{path}"
        ) from error


def pick_wine(candidates: Sequence[Path]) -> Path | None:
    """Return the first candidate that exists and is executable."""
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def proton_candidates() -> list[Path]:
    """List ``wine`` binaries from installed Proton runtimes, newest first."""
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


def detect_wine(explicit: Path | None) -> Path:
    """Locate a Wine binary and confirm it runs.

    Order: ``--wine``, ``$UNFIT_WINE``, ``wine`` on PATH, then Proton runtimes.

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

    wine = pick_wine(candidates) or pick_wine(proton_candidates())
    if wine is None:
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
        raise UnfitError(
            f"{wine} does not run: {result.stderr.strip() or result.stdout.strip()}"
        )
    logging.getLogger("unfit").info("using %s (%s)", wine, result.stdout.strip())
    return wine


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of ``path``."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def download_extractor(target: Path) -> None:
    """Download the pinned extractor release and verify its digest."""
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
    """Return a usable extractor path, fetching the pinned build if needed."""
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
            logging.getLogger("unfit").warning(
                "cached extractor failed its checksum, fetching it again"
            )
            download_extractor(candidate)
        return candidate
    if explicit is not None or env_path:
        raise UnfitError(f"extractor not found: {candidate}")
    download_extractor(candidate)
    return candidate


def build_extract_command(
    wine: Path,
    extractor: Path,
    pack_dir: Path,
    dest: Path | None,
    *,
    list_only: bool = False,
    skip_bin_check: bool = False,
    skip_verify: bool = False,
    verbose: bool = False,
    only: Sequence[str] = (),
) -> list[str]:
    """Assemble the extractor command line for Wine."""
    command = [str(wine), str(extractor), str(pack_dir)]
    if dest is not None and not list_only:
        command.extend(["-d", str(dest)])
    if list_only:
        command.append("--list")
    for volume in only:
        command.extend(["--only", volume])
    if skip_bin_check:
        command.append("--skip-bin-check")
    if skip_verify:
        command.append("--skip-verify")
    if verbose:
        command.append("--verbose")
    return command


def wine_environment() -> dict[str, str]:
    """Environment for the extractor: persistent prefix, quiet Wine."""
    environment = dict(os.environ)
    environment["WINEPREFIX"] = str(PREFIX_DIR)
    environment["WINEDEBUG"] = "-all"
    return environment


def run_streaming(
    command: Sequence[str],
    *,
    log_path: Path,
    dest: Path | None = None,
    total: int = 0,
    bar: ProgressBar | None = None,
    echo: bool = True,
    on_line: Callable[[str], None] | None = None,
) -> int:
    """Run the extractor, log its output, echo and show progress as asked.

    The child gets its own process group so Ctrl-C reaches Wine and every
    helper process it spawned.
    """
    start = time.monotonic()
    stop = threading.Event()

    def watch() -> None:
        if bar is None or not bar.enabled or dest is None:
            return
        while not stop.wait(PROGRESS_INTERVAL):
            bar.render(directory_size(dest), total, "unpacking", start)

    watcher = threading.Thread(target=watch, daemon=True)
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
        watcher.start()
        assert process.stdout is not None
        try:
            for line in process.stdout:
                if bar is not None:
                    bar.clear()
                log.write(line)
                if echo:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                if on_line is not None:
                    on_line(line)
            returncode = process.wait()
        except KeyboardInterrupt:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            with contextlib.suppress(subprocess.TimeoutExpired, ProcessLookupError):
                process.wait(timeout=30)
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            raise
        finally:
            stop.set()
            watcher.join(timeout=PROGRESS_INTERVAL + 1)
            if bar is not None:
                bar.clear()
    return returncode


def verify_bins(pack: PackFiles, bar: ProgressBar) -> VerifyReport:
    """Verify the ``.bin`` volumes against the repack's bins manifest."""
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
    """Missing volumes that are not optional selective downloads."""
    return [relative for relative in report.missing if not is_selective(relative)]


def destination_manifest(dest: Path) -> dict[str, str] | None:
    """Read ``_Redist/fitgirl.md5`` from an unpacked folder, if it has one."""
    manifest_path = dest / "_Redist/fitgirl.md5"
    if not manifest_path.is_file():
        return None
    return read_md5_manifest(manifest_path)


def repair_layout(dest: Path) -> None:
    """Move manifest files that unpacked to the root into their subfolder."""
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
SYNC_TOOLS = frozenset({"countdown.exe"})
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
    xdelta: Path | None


def split_cmd_words(text: str) -> list[str]:
    """Split a ``cmd.exe`` command line into words, honouring double quotes."""
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
    """Split ``a && b && c`` on ``&&`` outside double quotes."""
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
    """Return True for ``fitgirl2-path\\...`` arguments (the scripts folder)."""
    return bool(SCRIPT_PLACEHOLDER.match(argument))


def raw_options(args: Sequence[str]) -> tuple[list[str], dict[str, int]]:
    """Split ``raw.exe`` arguments into positionals and ``-ioff/-ilen/-ooff``."""
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
    """Return ``(source, patch, output)`` for an ``x.exe -d -s`` decode."""
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


def step_files(step: Step) -> StepFiles:
    """Validate a step and report the files it reads and writes."""
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
    raise UnfitError(f"unsupported post-install tool {step.tool}")


def check_script_path(argument: str) -> None:
    """Reject absolute paths and ``..`` so a script cannot leave the game folder.

    Raises:
        UnfitError: For paths that could point outside the destination.
    """
    pure = PureWindowsPath(SCRIPT_PLACEHOLDER.sub("", argument))
    if pure.drive or pure.root or ".." in pure.parts or not pure.parts:
        raise UnfitError(f"path not allowed in a post-install script: {argument}")


def parse_step(text: str, origin: str) -> Step:
    """Turn one command into a :class:`Step`, rejecting anything unknown."""
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
    """Labels, gotos, ``if ... goto`` waits and marker echoes need no replay.

    FitGirl's scripts poll for each other's marker files because the installer
    starts them together; unfit runs them one after another instead.
    """
    lowered = line.lower()
    return (
        not line
        or line.startswith(":")
        or lowered in {"rem", "@echo off", "echo off"}
        or lowered.startswith(("rem ", "goto ", "echo ", "@rem "))
        or (lowered.startswith("if ") and " goto " in f"{lowered} ")
    )


def parse_chain_text(line: str, origin: str) -> list[Step]:
    """Parse ``cmd /c "a && b"`` or a plain command into steps."""
    text = line.strip()
    if text.lower().startswith("cmd /c "):
        text = text[7:].strip()
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            text = text[1:-1]
    steps = [parse_step(part, origin) for part in split_and_chain(text)]
    return [step for step in steps if step.tool != "del" or step.args]


def parse_post_install_script(script: Path, scripts_root: Path) -> list[Batch]:
    """Parse one ``build*.bat`` into batches, expanding ``run.exe`` lists.

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
    """Expand ``run.exe " " URL LISTFILE N``: one chain per list line."""
    lists = [arg for arg in step.args if is_placeholder_path(arg)]
    if len(lists) != 1:
        raise UnfitError(f"{origin}: cannot find the command list for run.exe")
    list_path = resolve_case_insensitive(
        scripts_root, SCRIPT_PLACEHOLDER.sub("", lists[0])
    )
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
        """Folders ``d`` (relative to root) where ``d/relative`` is a file."""
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
    """Inputs a chain needs that no earlier step of the same chain creates."""
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


def locate_chain(index: FileIndex, chain: Chain) -> str | None:
    """Find the working folder a chain was written for.

    The installer starts each script in a folder the script never names, so
    the folder is the unique one that holds every input the chain reads.
    Delete-only chains use whichever of their targets still exist.

    Returns:
        The folder relative to the destination, or None when the inputs are
        gone (typically because the chain already ran).

    Raises:
        UnfitError: When several folders fit.
    """
    probes = chain_probes(chain)
    if probes:
        sets = [index.folders_holding(probe) for probe in probes]
    else:
        targets = [
            target
            for step in chain.steps
            for target in step.args
            if not is_placeholder_path(target)
        ]
        sets = [found for found in map(index.folders_holding, targets) if found]
    if not sets:
        return None
    common = set.intersection(*sets)
    if not common:
        return None
    if len(common) > 1:
        listing = ", ".join(sorted(folder or "." for folder in common))
        raise UnfitError(f"{chain.origin}: inputs found in several folders: {listing}")
    return common.pop()


def probes_exist(folder: Path, chain: Chain) -> bool:
    """Check a located folder against the disk, in case the index is stale."""
    return all(
        resolve_case_insensitive(folder, probe).is_file()
        for probe in chain_probes(chain)
    )


def to_wine_path(path: Path) -> str:
    """Spell a Linux path the way Wine's default ``Z:`` drive exposes it."""
    return "Z:" + str(path).replace("/", "\\")


def raw_copy(source: Path, target: Path, options: Mapping[str, int]) -> None:
    """Do what ``raw.exe IN OUT -ioff -ilen -ooff`` does, without truncating OUT."""
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
    """Run one helper program and raise with its output when it fails."""
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
        output = (result.stdout + result.stderr).strip().splitlines()[-3:]
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
        """Resolve a script argument and make sure it stays inside the game."""
        if is_placeholder_path(argument):
            base = self._context.scripts_root
            relative = SCRIPT_PLACEHOLDER.sub("", argument)
        else:
            base, relative = self._cwd, argument
        resolved = resolve_case_insensitive(base, relative)
        root = self._context.root.resolve()
        absolute = resolved.resolve()
        if absolute != root and root not in absolute.parents:
            raise UnfitError(f"post-install path leaves the destination: {argument}")
        return resolved

    def run(self, chain: Chain) -> None:
        """Run every step; on success, drop the files the chain deleted."""
        for step in chain.steps:
            try:
                self.run_step(step)
            except (UnfitError, OSError) as error:
                kept = f"; deleted files kept in {self._trash}" if self._deleted else ""
                raise UnfitError(f"{chain.origin}: {error}{kept}") from error
        if self._deleted:
            shutil.rmtree(self._trash, ignore_errors=True)

    def run_step(self, step: Step) -> None:
        """Replay one command."""
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
                    to_wine_path(self.path(step.exe)),
                    to_wine_path(source),
                    to_wine_path(target),
                ],
                self._cwd,
                wine=True,
            )
            if not target.is_file():
                raise UnfitError(f"fgpack.exe did not write {target.name}")
        elif step.tool == "x.exe":
            self.xdelta(step)
        else:
            raise UnfitError(f"unsupported post-install tool {step.tool}")

    def xdelta(self, step: Step) -> None:
        """Apply an xdelta3 patch, natively when ``xdelta3`` is installed."""
        source, patch, output = (self.path(arg) for arg in xdelta_operands(step.args))
        if self._context.xdelta is not None:
            command = [str(self._context.xdelta), "-f", "-d", "-s"]
            command += [str(source), str(patch), str(output)]
            run_tool(command, self._cwd, wine=False)
        else:
            command = [str(self._context.wine), to_wine_path(self.path(step.exe))]
            command += ["-f", "-d", "-s"]
            command += [to_wine_path(path) for path in (source, patch, output)]
            run_tool(command, self._cwd, wine=True)

    def delete(self, targets: Sequence[str]) -> None:
        """Move deleted files aside; they are removed once the chain succeeds.

        Files in the scripts folder are left alone so the scripts can be
        replayed again with ``--finish``.
        """
        for target in targets:
            if is_placeholder_path(target):
                continue
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


def run_batch(
    context: PostInstallContext,
    batch: Batch,
    index: FileIndex,
    tally: PostInstallTally,
    workers: int,
) -> FileIndex:
    """Run one batch and return a file index that is fresh enough to reuse."""
    planned: list[tuple[int, Chain, Path]] = []
    for number, chain in enumerate(batch.chains):
        try:
            folder = locate_chain(index, chain)
        except UnfitError:
            folder = None
        if folder is None or not probes_exist(context.root / folder, chain):
            index = FileIndex(context.root)
            folder = locate_chain(index, chain)
        if folder is None:
            tally.skipped += 1
            continue
        planned.append((number, chain, context.root / folder))

    trash_root = context.root / TRASH_DIR

    def execute(item: tuple[int, Chain, Path]) -> Chain:
        number, chain, cwd = item
        trash = trash_root / f"{batch.origin.replace(':', '-')}-{number}"
        ChainRunner(context, cwd, trash).run(chain)
        return chain

    if not batch.parallel or len(planned) <= 1:
        for item in planned:
            execute(item)
            tally.ran += 1
    else:
        print(f"  {batch.origin}: {len(planned)} commands in parallel", flush=True)
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(execute, item) for item in planned]
            try:
                for done, future in enumerate(cf.as_completed(futures), 1):
                    future.result()
                    tally.ran += 1
                    if done % 25 == 0 or done == len(futures):
                        print(f"    {done}/{len(futures)}", flush=True)
            except BaseException:
                for future in futures:
                    future.cancel()
                raise
        index = FileIndex(context.root)
    with contextlib.suppress(OSError):
        trash_root.rmdir()
    return index


def run_post_install(dest: Path, wine: Path, *, workers: int | None = None) -> int:
    """Replay FitGirl's ``build*.bat`` post-install scripts, if the pack has any.

    Every script is parsed before anything runs, so an unsupported command
    leaves the destination untouched.

    Returns:
        0 when there was nothing to do or everything ran, 1 on failure.
    """
    try:
        found = find_post_install_scripts(dest)
        if found is None:
            return 0
        scripts_root, scripts = found
        parsed = [
            (script, parse_post_install_script(script, scripts_root))
            for script in scripts
        ]
    except UnfitError as error:
        print(f"post-install: not replayed, {error}")
        return 1

    names = ", ".join(script.name for script in scripts)
    print(f"post-install: replaying {names} from {scripts_root.relative_to(dest)}")
    xdelta = shutil.which("xdelta3")
    context = PostInstallContext(
        root=dest,
        scripts_root=scripts_root,
        wine=wine,
        xdelta=Path(xdelta) if xdelta else None,
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
        print(f"post-install: FAILED at {error}")
        return 1
    summary = f"post-install: {tally.ran} command chain(s) ran"
    if tally.skipped:
        summary += f", {tally.skipped} skipped (inputs gone, already applied?)"
    print(summary)
    return 0


def check_destination(pack_dir: Path, dest: Path, overwrite: bool) -> None:
    """Reject a destination inside the pack and a folder that already has files."""
    if dest == pack_dir or pack_dir in dest.parents:
        raise UnfitError(f"destination is inside the pack: {dest}")
    confirm_overwrite(dest, overwrite)


def confirm_overwrite(dest: Path, overwrite: bool) -> None:
    """Refuse to unpack into a folder that already holds files."""
    if overwrite or not dest.exists():
        return
    if any(dest.iterdir()):
        raise UnfitError(f"destination is not empty: {dest} (use --overwrite)")


def log_path_for(pack: PackFiles) -> Path:
    """Build a timestamped log file path for this run."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return STATE_DIR / "logs" / f"{stamp}-{derive_dest_name(pack.pack_dir)[:40]}.log"


def run_check(pack: PackFiles, bar: ProgressBar) -> int:
    """Verify the ``.bin`` volumes and report the result."""
    report = verify_bins(pack, bar)
    print(f"bins: {describe_report(report, selective_missing=True)}")
    return 1 if report.bad or required_missing(report) else 0


def run_list(
    pack: PackFiles,
    tools: Toolchain,
    *,
    log_path: Path,
    verbose: bool,
    echo: bool,
) -> int:
    """Ask the extractor for the archive listing."""
    command = build_extract_command(
        tools.wine,
        tools.extractor,
        pack.pack_dir,
        None,
        list_only=True,
        verbose=verbose,
    )
    return run_streaming(command, log_path=log_path, echo=echo)


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
    """Record volumes the extractor reports as failed."""
    match = FAILED_VOLUME.match(line.strip())
    if match and match.group(1) not in failed:
        failed.append(match.group(1))


def parse_arc_tool_dirs(text: str) -> set[str]:
    """Folders that arc.ini runs external tools from (``tools\\xtool.exe``)."""
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
    """
    if not tool_dirs or destination_manifest(dest) is None:
        return
    for folder in tool_dirs:
        shutil.rmtree(folder, ignore_errors=True)
    names = ", ".join(f"{folder.name}\\" for folder in tool_dirs)
    print(f"removed installer tools {names} from the game folder")


def retry_with_tools(
    pack: PackFiles,
    tools: Toolchain,
    options: RunOptions,
    bar: ProgressBar,
    total: int,
    *,
    failed: Sequence[str],
    tool_dirs: Sequence[Path],
) -> int:
    """Unpack failed volumes again, with the tool folders next to the extractor.

    Returns:
        0 when every retried volume unpacked, 1 otherwise.
    """
    staging = options.dest / TOOL_STAGING_DIR
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    names = ", ".join(f"{folder.name}\\" for folder in tool_dirs)
    still_failed: list[str] = []
    try:
        extractor = staging / tools.extractor.name
        shutil.copy2(tools.extractor, extractor)
        for folder in tool_dirs:
            shutil.copytree(folder, staging / folder.name)
        for volume in failed:
            print(f"retrying {volume} with the installer tools {names}")
            again: list[str] = []
            command = build_extract_command(
                tools.wine,
                extractor,
                pack.pack_dir,
                options.dest,
                skip_bin_check=True,
                skip_verify=True,
                verbose=options.verbose,
                only=[volume],
            )
            code = run_streaming(
                command,
                log_path=options.log_path,
                dest=options.dest,
                total=total,
                bar=bar,
                echo=options.echo,
                on_line=functools.partial(collect_failed_volume, failed=again),
            )
            if code != 0 or again:
                still_failed.append(volume)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    if still_failed:
        print(f"still failing with the installer tools: {', '.join(still_failed)}")
        return 1
    return 0


def run_extract(
    pack: PackFiles,
    tools: Toolchain,
    options: RunOptions,
    bar: ProgressBar,
) -> int:
    """Run the full extract flow: verify bins, check space, unpack, verify."""
    if not options.skip_md5:
        report = verify_bins(pack, bar)
        print(f"bins: {describe_report(report, selective_missing=True)}")
        missing = required_missing(report)
        if report.bad:
            raise UnfitError(
                "volume checksum mismatch - delete and re-download those files"
            )
        if missing:
            raise UnfitError(f"missing volumes: {', '.join(missing)}")

    listing_command = build_extract_command(
        tools.wine, tools.extractor, pack.pack_dir, None, list_only=True
    )
    listing_parts: list[str] = []
    listing_code = run_streaming(
        listing_command,
        log_path=options.log_path,
        echo=False,
        on_line=listing_parts.append,
    )
    total = parse_unpacked_bytes("".join(listing_parts))
    if listing_code != 0 or total <= 0:
        raise UnfitError(
            "cannot read the archive listing; run `unfit --list` to see why"
        )

    options.dest.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(options.dest).free
    needed = total + SPACE_MARGIN
    if free < needed:
        raise UnfitError(
            f"not enough space on {options.dest}: "
            f"need {needed / 1024**3:.1f} GiB, have {free / 1024**3:.1f} GiB"
        )

    command = build_extract_command(
        tools.wine,
        tools.extractor,
        pack.pack_dir,
        options.dest,
        skip_bin_check=True,
        skip_verify=True,
        verbose=options.verbose,
    )
    print(
        f"unpacking {len(pack.bins)} volume(s), {total / 1024**3:.2f} GiB "
        f"into {options.dest}"
    )
    failed: list[str] = []
    with ArcIniCatcher(options.dest) as catcher:
        code = run_streaming(
            command,
            log_path=options.log_path,
            dest=options.dest,
            total=total,
            bar=bar,
            echo=options.echo,
            on_line=functools.partial(collect_failed_volume, failed=failed),
        )
    tool_dirs = (
        find_tool_dirs(options.dest, parse_arc_tool_dirs(catcher.text))
        if catcher.text
        else []
    )
    if failed and tool_dirs:
        code = retry_with_tools(
            pack, tools, options, bar, total, failed=failed, tool_dirs=tool_dirs
        )
    elif failed:
        print(
            "note: no installer tool folders from arc.ini were unpacked, "
            "so the failed volume(s) were not retried"
        )
    if code == 0:
        remove_tool_dirs(options.dest, tool_dirs)
    if code != 0:
        print(f"extractor exited with code {code}", file=sys.stderr)

    post_code = 0
    if code == 0 and not options.skip_post_install:
        repair_layout(options.dest)
        post_code = run_post_install(options.dest, tools.wine)
    verify_code = (
        post_extract_verify(options.dest, bar) if not options.skip_verify else 0
    )
    print_install_note()
    return 0 if code == 0 and post_code == 0 and verify_code == 0 else 1


def print_install_note() -> None:
    """Remind the user what an unpack does not do."""
    print(
        "note: _Redist installers, registry entries, shortcuts and install-script "
        "renames are not applied - run the redistributables if the game needs them"
    )


def run_finish(dest: Path, wine: Path, bar: ProgressBar, *, skip_verify: bool) -> int:
    """Replay post-install scripts on an already unpacked folder, then verify."""
    if not dest.is_dir():
        raise UnfitError(f"not a directory: {dest}")
    repair_layout(dest)
    post_code = run_post_install(dest, wine)
    verify_code = post_extract_verify(dest, bar) if not skip_verify else 0
    print_install_note()
    return 0 if post_code == 0 and verify_code == 0 else 1


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="unfit",
        description="Verify and unpack FitGirl repacks on Linux (via Wine).",
    )
    parser.add_argument(
        "pack_dir",
        type=Path,
        help="folder with setup.exe and fg-*.bin (with --finish: an unpacked folder)",
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
        help="do not replay the pack's work\\build*.bat post-install scripts",
    )
    parser.add_argument(
        "--finish",
        action="store_true",
        help="replay post-install scripts on an already unpacked folder, then verify",
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
        level=logging.INFO, format="unfit: %(message)s", stream=sys.stderr
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns a process exit code."""
    configure_logging()
    args = parse_args(argv)
    bar = ProgressBar(not args.no_progress and sys.stderr.isatty())

    try:
        if args.finish:
            return run_finish(
                args.pack_dir.expanduser().resolve(),
                detect_wine(args.wine),
                bar,
                skip_verify=args.skip_verify,
            )
        pack = find_pack_files(args.pack_dir.expanduser().resolve())
        if args.check:
            return run_check(pack, bar)

        tools = Toolchain(detect_wine(args.wine), ensure_extractor(args.extractor))
        log_path = log_path_for(pack)
        if args.list:
            return run_list(
                pack,
                tools,
                log_path=log_path,
                verbose=args.verbose,
                echo=not args.quiet,
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
                tools.wine,
                tools.extractor,
                pack.pack_dir,
                dest,
                skip_bin_check=True,
                skip_verify=True,
            )
            print(
                f"would verify {len(pack.bins)} volume(s) against {pack.bins_manifest}"
            )
            print(f"would run: {shlex.join(command)}")
            if dest.exists() and any(dest.iterdir()):
                print("note: destination is not empty, a real run needs --overwrite")
            return 0

        check_destination(pack.pack_dir, dest, args.overwrite)

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
        print(f"unfit: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nunfit: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
