# unfit

Verify and unpack FitGirl repacks on Linux, without remembering the Wine
incantation.

> [!CAUTION]
> unfit does not work with every repack. It has been tested on a handful of
> packs only, and is unofficial: not affiliated with FitGirl or with
> fitgirl-extractor.
>
> - Only packs whose `setup.exe` is Inno Setup and ships `unarc.dll` (FreeArc)
>   can be unpacked. Each compression method also needs a 64-bit helper that
>   works under Wine; methods the tested packs did not use may fail.
> - Post-install steps are replayed only when they use the commands listed
>   under [Post-install scripts](#post-install-scripts) and
>   [Install-script commands](#install-script-commands); anything else is
>   reported and skipped, and the affected files will fail verification.
> - It is not an installer: redistributables, registry entries and shortcuts
>   are not applied.
>
> Keep the `.bin` files until the final check reports `0 bad, 0 missing`.

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
  scripts and the rebuild commands in its install script, and verifies every
  file.

## Requirements

- Linux, Python 3.10+
- Wine with WoW64 support. Any prefix works; a Proton build is detected
  automatically (`~/.steam/steam/steamapps/common/Proton*`). On Fedora,
  Proton Experimental from Steam is enough — no system Wine needed.
- `fitgirl-extractor.exe` v0.2.1 is downloaded on first use into
  `~/.local/share/unfit/` and checked against a pinned SHA-256.
- `xdelta3`, only for packs whose post-install scripts apply xdelta patches.
- `innoextract`, only for packs whose install script rebuilds files with
  helpers it carries (see [Install-script commands](#install-script-commands)).

When a required tool is missing, unfit names it and exits (code 2). A
missing `xdelta3` or `innoextract` is noticed after unpacking, when the
post-install steps are read: install it, then run
`unfit --finish PACK_DIR -d DEST` to replay them.

## Install

```sh
ln -sf "$PWD/unfit.py" ~/.local/bin/unfit
```

## Usage

```
unfit PACK_DIR [-d DEST]        verify .bin volumes, then unpack
unfit --check PACK_DIR          verify .bin volumes only
unfit --list PACK_DIR           list archive contents
unfit --finish PACK_DIR -d DIR  replay post-install steps on an unpacked DIR
unfit --finish DIR              same, without the commands in setup.exe
```

| Option | Meaning |
| --- | --- |
| `-d, --dest DIR` | destination (default `~/Games/<pack name without the [tag]>`) |
| `--check` | hash the `.bin` volumes against the manifest, extract nothing |
| `--list` | ask the extractor for the archive listing |
| `--skip-md5` | skip volume verification (trusts the files) |
| `--skip-verify` | skip the post-extraction verification |
| `--no-post-install` | do not replay `work\build*.bat` or the install-script commands (see below) |
| `--finish` | work on an already unpacked folder: repair, replay post-install steps, verify. With `-d DIR`, the argument is the pack folder (its `setup.exe` is read for install-script commands) and `DIR` the unpacked folder |
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
5. Retries volumes that failed because they need a tool from another volume
   (below).
6. Repairs the layout, replays post-install scripts and install-script
   commands (all below).
7. Verifies the result against `_Redist/fitgirl.md5`, hashing up to eight
   files at a time.

### Layout repair

FitGirl's `setup.exe` normally moves the unpacked payload into place as part of
its install script (`games\<name>.nup`). Skip the installer and the file lands
in the destination root, so a naive check reports
`40 ok, 0 bad, 1 missing`. `unfit` detects that case, confirms the file's MD5
matches the manifest entry, moves it to the recorded path, and re-verifies — so
that repack ends with `41 ok, 0 bad, 0 missing` and exit `0`.

### Installer tools in a volume

Some packs ship an external decompressor in a volume of its own and run it by
a relative path from `arc.ini`, for example a small volume holding
`tools\xtool.exe` while the main volume is unpacked with:

```ini
[External compressor:example]
unpackcmd = tools\xtool.exe decode -t100p - - <stdin> <stdout>
```

The installer unpacks that volume into its temp folder first. The extractor
unpacks every volume into the game folder and runs `unarc.dll` from a temp
folder it recreates on every run, so the main volume fails right away with
`archive data corrupted (decompression fails)`.

`unfit` copies `arc.ini` out of the extractor's work folder while the
extractor runs. If a volume fails and a folder that `arc.ini` runs tools from
(and that `_Redist/fitgirl.md5` does not list as game files) was unpacked, it:

1. puts a copy of `fitgirl-extractor.exe` and those folders into
   `DEST/.unfit-tools/` (Wine looks for a relative program name like
   `tools\xtool.exe` in the running exe's folder first),
2. unpacks each failed volume again with that copy (`--only`),
3. removes `.unfit-tools/` and, once everything unpacked, the tool folders
   from the game folder, where the installer never puts them.

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
- `x.exe -d -s SRC PATCH OUT`: run as the native `xdelta3`
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

### Install-script commands

Other repacks rebuild files from the install script itself. After unpacking
some volumes into a game subfolder, its `[Code]` section runs helpers it
carries in `{tmp}`, for example:

```
cd {app}\Game\Content\Paks
{tmp}\x5.exe -s-2g 1.fgpack archive.pak.x5 archive.pak && del 1.fgpack archive.pak.x5
{tmp}\x5.exe -s-2g 2.fgpack archive.pak.x2d_a.x5 archive.pak.x2d_a && del ...
{tmp}\x2n.exe archive.pak archive.pak.x2d_a archive.pak.x2m_a && del ...
```

`x5.exe` is HDiffPatch's `hpatchz` (OLD + DIFF gives NEW); `x2n.exe` patches
extra data into the archive in place. The extractor puts the inputs in the game
root and never runs these commands, so the archive is simply missing.

`unfit` reads the compiled script from `setup.exe` without running it: it
decodes the setup header (LZMA, with Inno Setup's chunk checksums) and walks
the script's string literals, which are stored in program order. A command is
the literal sequence `{app}\FOLDER\`, `/C `, `{tmp}\TOOL`, `ARGS`, `{cmd}`.
Only `x5.exe` (options `-m`, `-s[-SIZE]`) and `x2n.exe` (three files), each
optionally followed by `del`, are accepted; Inno constants, `..`, absolute
paths or other programs in `ARGS` stop the replay before anything runs. Tools
that only work on the installer's temp files (e.g. `fnr.exe` rewriting
`arc.ini`) are ignored; other tools run in the game folder are reported.

For each command, in order:

1. inputs are looked for in `FOLDER`, then in the root; inputs in the root are
   moved into `FOLDER`, where the installer would have unpacked them,
2. if an input is missing (the command already ran, or an optional volume was
   not unpacked), the command is skipped,
3. otherwise the helper, unpacked from `setup.exe` with `innoextract` into
   `DEST/.unfit-tools/`, runs under Wine in `FOLDER`. An output left by an
   interrupted run is moved aside first, because `hpatchz` refuses to
   overwrite it, and `del` works as in the scripts above.

`unfit --finish DIR` alone cannot read the installer; use
`unfit --finish PACK_DIR -d DIR` on a folder unpacked by an older unfit.

## Limitations

`unfit` does not run FitGirl's other install steps: redistributables in
`_Redist\` (e.g. `vc_redist.x64.exe`), registry entries, shortcuts, or renames
the install script performs on other files. Install the redistributables into
the game's Wine prefix if the launcher needs them. Post-install steps that
use commands other than the ones listed above are reported and not replayed.
Install-script commands are only found in Inno Setup 5.1.5+ installers whose
loader table and setup header have the layout described above.

Paths must be representable in Windows-1252 (basically ASCII), and only repacks
whose `setup.exe` ships `unarc.dll` are supported.

## Development

```sh
uv run pytest      # unit and end-to-end tests (the latter use a fake wine)
uv run ruff format . && uv run ruff check .
uv run mypy --strict     # unfit.py and tests/
```
