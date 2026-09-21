# Changelog

Notable changes per release. Full per-version history lives in the module
docstring at the top of `mAIpper.py`; releases are tagged `vX.Y`.

## v0.17

One-line bugfix release, closing the gap the v0.16 refactor found and
deliberately left open.

### Fixed

- **NXC writer now preserves `## Access`.** `_write_nxc_host_enrichment` has
  never carried forward an existing `## Access` section, unlike the other
  five host-note writers -- a host enriched via NXC after having confirmed
  access recorded (via `/merge`, `+access`, or manual edit) would silently
  lose that table on the next NXC run. This bug predates v0.16; it was only
  discovered while writing that release's section-dict serializer, which
  deliberately kept it (rather than fixing it inside a commit whose whole
  point was proving it changed no behaviour) so the golden-snapshot diff
  proving the refactor safe stayed genuinely empty. This release removes the
  one line that dropped the section. `tests/golden/nxc_merge.md` regenerated
  and reviewed; the diff is exactly the `## Access` block appearing, nothing
  else changed.

## v0.16

Follow-up to the v0.15 audit: the roadmap item the audit itself flagged as
highest priority (a single serializer for host-note writers) now exists,
verified with golden-output tests, plus infrastructure to keep the version
number itself from drifting the way `--help` once did.

### Added

- **Golden-output tests** (`tests/test_writer_output.py`). Each of the six
  host-note writers is snapshotted in two scenarios (write a fresh note,
  merge into a note already holding content from every other source). These
  assert output is *unchanged*, not *correct* — the right check for a
  refactor, which by definition should not alter behaviour. `tests/fixtures.py`
  holds inputs shared with `tests/test_note_writing.py` so the two suites
  cannot drift apart.
- **`tests/test_version.py`** and **`__version__`** as the single source of
  truth for the release version, read by `--version`, `--help`, and the
  interactive header. Previously the version existed only as prose in the
  module docstring — there was no way to tell which release was running
  without opening the file, and a second copy in the `argparse` description
  had silently drifted two releases behind (`--help` said v0.13 while the
  docstring said v0.15). The test now fails if any copy of the version, or
  the docstring header, or the CHANGELOG goes out of step.
- `--version` flag.

### Changed

- **Section-dict serializer for host notes.** The six writers
  (`_write_host_note`, `_update_host_note_nessus/burp/autorecon/loot`,
  `_write_nxc_host_enrichment`) no longer hand-list all 11 body sections as
  repeated `if existing_X: lines += [...]` chains — the exact duplication
  that produced v0.15's frontmatter bug, where a section preserved by five
  writers was silently dropped by the sixth. `_read_host_note_state()` now
  reads frontmatter, preamble, and every body section into one dict; a
  writer overwrites the entry for the section it owns and
  `_render_host_note_body()` re-emits everything in `BODY_SECTION_ORDER`.
  Net -244 lines in `mAIpper.py`. Verified behaviour-identical: all 13
  golden snapshots passed with zero diffs against pre-refactor output, plus
  a clean end-to-end run against synthetic multi-source scan data.

### Known issue found (not yet fixed)

Refactoring surfaced a real bug that predates this release: **the NXC writer
has never preserved an existing `## Access` section**, unlike the other five
host-note writers — contradicting the v0.14 changelog's claim that all six
were fixed. The v0.16 refactor deliberately keeps this bug (rather than
silently fixing it inside a "behaviour-preserving" refactor commit) so the
golden-snapshot diff proving the refactor is safe stayed genuinely empty.
Tracked as `CLAUDE.md` known gap #14 and priority #1 on the roadmap — the fix
is one line plus regenerating two golden snapshots.

## v0.15

A full-codebase audit found four crashes and two data-loss bugs. Each was
reproduced with a runnable test before being fixed, and those tests ship as
`tests/test_note_writing.py` (11 of its 12 cases fail against v0.14).

### Upgrade note

**If you cloned this repo and `--init` failed, that was a bug, not your setup.**
`python mAIpper.py --init` raised `NameError: name 'args' is not defined` on
every invocation and exited before creating `maipper.conf`, `docs/`, and the
Assessment Config. Normal runs auto-generated the config separately, which is
why the tool still worked if you skipped `--init`. Fixed — first-run onboarding
now completes.

No migration is needed. Existing vaults are picked up as-is, and the
frontmatter fix below starts preserving fields on the next write.

### Fixed — crashes

- **`--init` never worked.** `_init_scan_dirs` referenced a module-global `args`
  that does not exist. Now takes `vault_dir` as a parameter.
- **`/analyze` and `/deepdive` crashed on backslashes in model output.** Both
  passed raw LLM output as an `re.sub` *replacement template*, where backslash
  sequences are parsed as escapes or group references. Domain-qualified
  usernames, Windows paths and UNC paths all raised `re.error: bad escape`. The
  exception was swallowed, so the analysis was lost and the LLM call wasted.
  Section writes now insert content verbatim.
- **Any run with loot credentials aborted.** `_CRED_TABLE_ROW_RE` was defined
  twice; the later loose 1-group matcher shadowed the 6-group column parser, so
  rebuilding the Campaign-Level aggregates in `Loot/Credentials.md` raised
  `IndexError: no such group`. The loose matcher is now
  `_CRED_TABLE_ANY_ROW_RE`.
- **`UnicodeEncodeError` on Windows.** Arrows and box-drawing characters in CLI
  output crashed whenever stdout was redirected under a legacy codepage.
  stdout/stderr are reconfigured to UTF-8 at startup.

### Fixed — data loss

- **Deep dive results were silently discarded.** If a host note had a blank line
  between `## Analysis` and its first content — standard Markdown, and what
  Obsidian produces on edit — the write was a no-op, while the checkbox still
  flipped to `[/]` (green/done). Section writes are now index-based instead of
  reconstructing the old section as an exact string, so whitespace drift cannot
  swallow a result.
- **Host-note writers dropped frontmatter they did not own.** Each of the six
  writers rebuilt `fm` from scratch. `ips` — written only by `/merge` — was
  dropped by **all six**, silently un-merging multi-interface hosts on the next
  scan. `loot_file_count`, `loot_credential_count`, `loot_hash_count` and
  `autorecon_tools_run` were dropped by most, so the Assessment Canvas, Priority
  Targets, Excel export and `/status` under-reported after a re-scan. A single
  `_carry_forward_fm` helper over `PRESERVED_FM_KEYS` now guards every writer.

### Fixed — correctness

- `validate_ai_output` read `target["nmap_scans"]`, a key the AutoRecon parser
  never writes, so port hallucination checking was a silent no-op for AutoRecon.
  It now parses `nmap_xml_files`.
- `/analyze` on an AutoRecon scan note only ever re-analyzed `targets[0]`; it now
  matches the target named by the note.
- The `/api/generate` fallback passed `temperature` at the top level instead of
  under `options`, silently discarding `--temperature` — the primary
  hallucination control was off in the fallback path.
- NXC SQLite connections are closed in a `finally` block instead of leaking when
  a query raises.

### Added

- `tests/test_note_writing.py` — regression tests for section writes,
  backslash-bearing LLM output, and frontmatter preservation across all writers.
  Runs standalone (`python tests/test_note_writing.py`) or under pytest; writes
  only into temp directories.
- **`--version` flag**, and `__version__` as the single source of truth. The version
  previously existed only as prose in a docstring, so there was no way to tell which
  release you were running without opening the file — and the `--help` description had
  silently drifted two releases behind (it said v0.13). `tests/test_version.py` now fails
  if any copy of the version goes stale or the CHANGELOG lacks an entry.
- `--rag-max-chunks N` and `--no-auto-build`. The documented `[rag] max_chunks`
  and `[rag] auto_build` config options were parsed but never reached `args`, so
  both were no-ops. They now take effect, and `--no-auto-build` suppresses the
  blocking startup prompt in batch runs.

### Changed

- Removed dead code: `_cosine_similarity`, `_decode_embedding_f16`, an unused
  `threading.local()`, an unreachable `_skip_words` re-check, the unused
  `base64` import, and the dead `no_excel` config mapping.
- Example hostnames and hashes in comments, docs and strings are now generic
  (`corp-ws01`, `dc01.corp.local`, `<32 hex chars>`). A new Key Conventions rule
  keeps engagement- and lab-specific values out of the repo.
- Roadmap reprioritised: the single section-dict serializer for host notes moves
  to priority 1, ahead of post-exploitation tracking. The v0.15 frontmatter bug
  was that gap cashing out, and post-ex tracking would add a seventh section to
  all six hand-maintained writers.

## v0.14

Host-note section preservation (`## Access`, `## NXC Enumeration`,
`## Cross-Source Analysis`), atomic vault writes via `_atomic_write_text`,
vectorized numpy RAG retrieval, `--workers` extended to AutoRecon/loot/misc,
fence-aware `extract_body_section`.

## v0.13

PlexTrac integration (`Findings/` notes, CSV export, `--plextrac`), Injestor
smart detection with NetExec and kiwi/secretsdump fast paths, `/chat` prefix
required for LLM questions.

## v0.12 and earlier

See the module docstring in `mAIpper.py` and the `v0.10`–`v0.12` tags.
