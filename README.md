# vncwipe

`vncwipe` (`vcnwipe.exe`) is a small, dependency-free NTFS secure-wipe utility
for Windows. It zeroes the logical contents of files — including **all NTFS
alternate data streams (ADS)** on files and directories — then deletes them,
with optional raw-cluster verification.

Key properties:

- **All-stream wiping** – every `$DATA` stream (default + named ADS) of a file
  or directory is overwritten before anything is deleted. If any stream is
  resident in the MFT or otherwise unsupported, the item is reported and **not
  deleted**.
- **Delete-pending freeze** – files are marked delete-pending *before* the
  overwrite, so a concurrent writer racing the wipe is detected instead of
  silently producing a non-zero file.
- **Rollback on failure** – if anything goes wrong between arming the
  delete-pending state and committing it, the state is rolled back (a rollback
  failure is explicitly reported, not swallowed).
- **Dry-run parity** – `--dry-run` performs the same eligibility checks and
  opens with the same access rights as the real run, so `Would wipe/delete`
  and `Would skip` match the real `Wiped`/`Skipped` counters.
- **Raw-LCN verification** – after wiping, the actually allocated clusters
  (VCN→LCN mapping) are read back via the raw volume and must read as zero
  (requires Administrator; can be skipped with `--no-verify`).
- **Reparse points are never followed.**

## Requirements

- Windows 10/11, NTFS volume
- MSVC (`cl.exe`) to build – single source file, no dependencies
- Administrator rights only needed for raw-LCN verification
  (omit `--no-verify` to verify; use `--no-verify` without elevation)

## Build

From a Visual Studio Developer Command Prompt:

```bat
cl /nologo /W4 /EHsc /O2 vcnwipe.cpp
```

Warning-free under `/W4`.

## Usage

```text
vcnwipe [--verify|--wipe|--wipe-slack] [-r|--recursive]
        [--no-verify] [--dry-run] [-y|--yes]
        [-v|--verbose] <file|directory>

--verify      read-only verification
--wipe        zero logical file contents
--wipe-slack  additionally zero slack in final allocated cluster
-r, recursive wipe files inside a directory, then delete
              files and directories (reparse points are never followed)
--no-verify   skip raw-LCN verification (no Administrator needed)
--dry-run     only list what would be wiped/deleted
              (same eligibility checks and open rights as the real run;
               with --verify: list what would be verified)
-y, --yes     skip the confirmation prompt for directories
-v, verbose   print VCN->LCN block list
```

Directories require `-y`/`--yes` (or an interactive confirmation).
Single-file outcomes go to stderr; per-item tags (`SKIP`/`WIPED`/`DRY`) and
the summary counters go to stdout.

Exit codes:

| Code | Meaning                                             |
| ---- | --------------------------------------------------- |
| `0`  | fully completed (everything wiped/verified)         |
| `1`  | partial: skips, unsupported or failed items remain  |
| `2`  | invalid command line                                |

## Limitations (by design)

- Small files (or streams) resident in the NTFS MFT have no LCN extents and
  cannot be wiped (reported as `UNSUPPORTED`).
- Raw-LCN verification only proves that the **currently allocated** clusters
  read back as zero. It does **not** prove that older copies no longer exist
  in SSD flash cells, storage firmware, snapshots, backups, or other layers.

## Safety model

- Without `DELETE` access on a directory, its ADS are left untouched and the
  item is reported as `Skipped` (same result in dry-run and real run).
- If a directory cannot be emptied (remaining skips/failures), it is kept and
  reported instead of being force-removed.
- The tool never follows reparse points and never wipes without an explicit
  mode flag.
