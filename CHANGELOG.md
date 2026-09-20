# Changelog

Notable changes per release. Full per-version history lives in the module
docstring at the top of `mAIpper.py`; releases are tagged `vX.Y`.

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
