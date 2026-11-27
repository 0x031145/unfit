# unfit

Verify and unpack FitGirl repacks on Linux, without remembering the Wine
incantation.

```sh
unfit /path/to/repack/
```

## Why this exists

FitGirl `.bin` volumes are FreeArc archives produced by **FitGirl's own modified
FreeArc** (`unarc.dll`, shipped inside `setup.exe`). Stock `unarc` builds fine
on Linux but rejects them with
`ERROR: archive structure corrupted (descriptor failed CRC check)`, because the
block checksums do not follow stock FreeArc conventions. The archive payloads
are still ordinary data, so the only supported way to unpack them is FitGirl's
own DLL — driven by
[`pisek/fitgirl-extractor`](https://github.com/pisek/fitgirl-extractor), which
unpacks `setup.exe` with innoextract, patches the CLS shared-memory namespace
mismatch, and calls `FreeArcExtract` in a worker process under Wine.

`unfit` wraps that tool and adds the parts that are easy to get wrong:

- hashes the `.bin` volumes against `MD5/fitgirl-bins.md5` **once** (a 20 GB
  volume takes under a minute), and passes `--skip-bin-check` to the extractor
  so the data is not hashed twice;
- rejects paths `unarc.dll` cannot represent (it takes ANSI paths);
- checks free space against the real unpacked size before writing 20+ GB;
- keeps a persistent Wine prefix and silences Wine's diagnostics;
- shows progress from destination growth against the known total;
- repairs the layout afterwards (see below), replays the pack's post-install
  scripts, and verifies every file.

## Requirements

- Linux, Python 3.10+
- Wine with WoW64 support. Any prefix works; a Proton build is detected
  automatically (`~/.steam/steam/steamapps/common/Proton*`). On Fedora,
  Proton Experimental from Steam is enough — no system Wine needed.
- `fitgirl-extractor.exe` v0.2.1 is downloaded on first use into
  `~/.local/share/unfit/` and checked against a pinned SHA-256.

## Install

```sh
ln -sf "$PWD/unfit.py" ~/.local/bin/unfit
```

## Usage

```
unfit PACK_DIR [-d DEST]        verify .bin volumes, then unpack
unfit --check PACK_DIR          verify .bin volumes only
unfit --list PACK_DIR           list archive contents
unfit --finish DIR              replay post-install scripts on an unpacked DIR
```

| Option | Meaning |
| --- | --- |
| `-d, --dest DIR` | destination (default `~/Games/<pack name without the [tag]>`) |
| `--check` | hash the `.bin` volumes against the manifest, extract nothing |
| `--list` | ask the extractor for the archive listing |
| `--skip-md5` | skip volume verification (trusts the files) |
| `--skip-verify` | skip the post-extraction verification |
| `--no-post-install` | do not replay `work\build*.bat` (see below) |
| `--finish` | treat the argument as an already unpacked folder: repair, replay post-install scripts, verify |
| `--overwrite` | allow a non-empty destination |
| `--extractor PATH` | use another `fitgirl-extractor.exe` |
| `--wine PATH` | use another Wine binary |
| `--no-progress` | no progress line (useful in logs) |
| `-q, --quiet` | hide extractor output; unfit's own lines still print |
| `-v, --verbose` | ask the extractor for per-file detail |
| `--dry-run` | print the commands that would run |

Environment: `UNFIT_WINE`, `UNFIT_EXTRACTOR`, `UNFIT_DATA_DIR`,
`UNFIT_STATE_DIR`.

Exit codes: `0` success (including repaired layouts), `1` verification or
extraction failure, `2` environment or usage error, `130` interrupted.

## What it does

1. Finds `setup.exe`, the `fg-*.bin` volumes and `MD5/*.md5`.
2. Hashes each present volume; missing `fg-selective-*` volumes are ignored
   (FitGirl treats them as optional), anything else aborts.
3. Runs `fitgirl-extractor --list` to learn the exact unpacked size, creates the
   destination, then checks free space.
4. Unpacks with `--skip-bin-check --skip-verify`, streaming and logging the
   extractor output to `~/.local/state/unfit/logs/` (one log per run).
5. Repairs the layout, replays post-install scripts (both below).
6. Verifies the result against `_Redist/fitgirl.md5`.

### Layout repair

FitGirl's `setup.exe` normally moves the unpacked payload into place as part of
its install script (`games\<name>.nup`). Skip the installer and the file lands
in the destination root, so a naive check reports
`40 ok, 0 bad, 1 missing`. `unfit` detects that case, confirms the file's MD5
matches the manifest entry, moves it to the recorded path, and re-verifies — so
that repack ends with `41 ok, 0 bad, 0 missing` and exit `0`.

### Post-install scripts

Some repacks store data in a smaller form and rebuild it after unpacking, with
batch scripts in `work\work\build*.bat`. A typical set ships video files
packed plus an xdelta patch each, and leaves the regions those files occupy
inside a game archive zeroed:

| Step | What it does |
| --- | --- |
| first script | `run.exe` runs every line of a command list: `fgpack.exe` unpacks a file, `x.exe` (xdelta3) patches it back to the original |
| second script | `raw.exe` copies each file into the archive at a fixed offset |
| last script | deletes a placeholder file |

Without these steps the rebuilt files and the archive fail verification.
`unfit` replays them after unpacking, and it does **not** hand the scripts to
`cmd.exe`. It parses them and accepts only commands it knows:

- `fgpack.exe IN OUT`: run under Wine, from the pack's `work` folder
- `x.exe -d -s SRC PATCH OUT`: native `xdelta3` when installed, otherwise
  `x.exe` under Wine
- `raw.exe IN OUT [-ioff=N] [-ilen=N] [-ooff=N]`: done in Python, writes into
  OUT without truncating it
- `run.exe ... LIST ...`: the list's command chains run in parallel (half the
  CPU threads)
- `del`: files are moved aside and removed only after their chain succeeds
- labels, `goto`, `if not exist ... goto`, `countdown.exe` and `echo` markers
  only sync scripts that the installer starts together, so they are skipped
  (unfit runs the scripts one after another)

Anything else (other programs, wildcards, absolute paths, `..`) stops the
replay **before** anything runs, and the files stay as unpacked. The scripts
never name their working folder, so `unfit` uses the one folder that holds
every input a chain reads (names match case-insensitively, as on Windows).
Two candidate folders count as an error. The scripts and tools in `work\` are
kept, so `unfit --finish DIR` can replay them on a folder that was unpacked
earlier. Chains whose inputs are already gone count as skipped.

If a chain fails, the run stops. Files that chain had deleted stay in
`DIR/.unfit-trash/`, and later scripts do not run.

## Limitations

`unfit` does not run FitGirl's other install steps: redistributables in
`_Redist\` (e.g. `vc_redist.x64.exe`), registry entries, shortcuts, or renames
the install script performs on other files. Install the redistributables into
the game's Wine prefix if the launcher needs them. Post-install scripts that
use commands other than the ones listed above are reported and not replayed.

Paths must be representable in Windows-1252 (basically ASCII), and only repacks
whose `setup.exe` ships `unarc.dll` are supported.

## Development

```sh
uv run pytest      # unit and end-to-end tests (the latter use a fake wine)
uv run ruff format . && uv run ruff check .
uv run mypy --strict unfit.py
```
