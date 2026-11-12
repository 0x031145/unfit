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
import contextlib
import dataclasses
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
from pathlib import Path, PurePosixPath
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
) -> list[str]:
    """Assemble the extractor command line for Wine."""
    command = [str(wine), str(extractor), str(pack_dir)]
    if dest is not None and not list_only:
        command.extend(["-d", str(dest)])
    if list_only:
        command.append("--list")
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


def post_extract_verify(dest: Path, bar: ProgressBar) -> int:
    """Repair misplaced files, then verify the destination against FitGirl's list.

    Returns:
        Process exit code: 0 when everything verified, 1 otherwise.
    """
    manifest_path = dest / "_Redist/fitgirl.md5"
    if not manifest_path.is_file():
        print(
            "no _Redist/fitgirl.md5 to verify against; skipping post-extraction check"
        )
        return 0

    manifest = read_md5_manifest(manifest_path)
    moves = plan_root_fixups(dest, manifest)
    for move in moves:
        print(
            f"repairing layout: {move.source.name} -> {move.target.relative_to(dest)}"
        )
    apply_moves(moves)

    report = verify_against_manifest(dest, manifest, bar)
    print(f"verified {report.total} files: {describe_report(report)}")
    for entry in report.bad:
        print(f"  BAD     {entry.path}: expected {entry.expected}, got {entry.actual}")
    for relative in report.missing:
        print(f"  MISSING {relative}")
    return 0 if report.clean else 1


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
    code = run_streaming(
        command,
        log_path=options.log_path,
        dest=options.dest,
        total=total,
        bar=bar,
        echo=options.echo,
    )
    if code != 0:
        print(f"extractor exited with code {code}", file=sys.stderr)

    verify_code = (
        post_extract_verify(options.dest, bar) if not options.skip_verify else 0
    )
    print(
        "note: _Redist installers, registry entries, shortcuts and install-script "
        "renames are not applied - run the redistributables if the game needs them"
    )
    return 0 if code == 0 and verify_code == 0 else 1


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="unfit",
        description="Verify and unpack FitGirl repacks on Linux (via Wine).",
    )
    parser.add_argument(
        "pack_dir", type=Path, help="folder with setup.exe and fg-*.bin"
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
