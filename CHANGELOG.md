# Changelog

Notable changes per release. Full per-version history lives in the module
docstring at the top of `mAIpper.py`; releases are tagged `vX.Y`.

## v0.19

Reported by an operator mid-engagement: Loot/Credentials.md was corrupted,
an LSA Secrets Dump credential never reached its host's note, and a
confirmed EternalBlue/MS17-010 exposure on a domain controller didn't stand
out anywhere in the vault.

### Added

- **Confirmed Nmap NSE vulnerability findings are now surfaced deterministically.**
  `parse_nmap_xml` now parses `<hostscript>` (host-level NSE results — e.g.
  `smb-vuln-ms17-010` — live there, not nested under any `<port>`, so they
  were silently dropped entirely and only ever reached the analysis as LLM
  guesswork). Any script result carrying the standard vulns.lua
  `State: VULNERABLE` marker (covers `smb-vuln-ms17-010`, `ssl-heartbleed`,
  and dozens of other `*-vuln-*` scripts generically, not just MS17-010) is
  extracted and written to a new, always-visible `## Critical Findings`
  host-note section plus a `critical_flags` frontmatter list. The static
  Priority Targets fallback now ranks a `critical_flags` host above pure
  port-count/Nessus-severity ties, the AI-ranked Priority Targets prompt is
  instructed to do the same, and the Nmap analysis prompt is given the
  confirmed findings as ground truth so it leads with them instead of
  re-deriving (or mis-deriving) them from the version banner.
- **Operator Notes on Injestor/Misc scan notes now guide a real credential
  re-extraction, not just commentary.** Write a correction like "it missed
  the cleartext password in the comment from that LDAP dump, make sure this
  gets entered" into a Misc-labeled note's new `## Operator Notes` section
  and re-run `/analyze`: the note's original content is re-sent for
  extraction with that note as guidance, and anything genuinely new lands
  directly in `Loot/Credentials.md` and the relevant host's `## Loot`
  section — not just echoed back as prose in `## Analysis`.

- **Per-host `## Creds` table.** Every host note now has a
  `Username | Password | Notes` table, between `## Critical Findings` and
  `## Open Ports`, for recording credentials straight on the host instead
  of going through the Injestor. Rows are pushed into that host's section of
  `Loot/Credentials.md` on every run and whenever a host note changes in
  interactive mode. The Password column takes a cleartext password or a
  hash (detected and filed in the Hash column), and `hash:cracked` works the
  same way it does elsewhere. Sync is one way and idempotent: a username
  already in that host's section is not added again, so rows stay in the
  table as the host's own record. Existing host notes get the empty table
  inserted on the next run, no re-scan needed, and `/merge` combines two
  notes' tables into one.
- **Pivot tracking.** The Injestor has a new `## Pivots` section: write one
  pivot per line in plain words (`ligolo agent on web01 gives access to
  172.16.2.0/24`, `pivot from 10.10.10.5 to dc02 with chisel`,
  `web01 -> dc02 -> 10.10.20.0/24`). A Python parser (no LLM) picks out
  hosts (IPs or names already in `Hosts/`), subnets (CIDR or `172.16.2.x`),
  the tool (ligolo, chisel, sshuttle, ssh tunnels, autoroute…) and the
  direction. Lines it can't resolve are listed in the archive note and
  printed, never guessed. Pivots land in a new `Pivots.md` table, the
  source of truth, which you can also edit by hand. From it, each host
  note gets a generated `## Pivots` section ("gives access to" / "reached
  through", including hosts reached via a pivoted subnet), and the
  Assessment Canvas gets purple edges labelled with the tool, plus a
  **Pivot Paths** panel showing whole chains. Targets not on the canvas
  yet get their own card. In interactive mode, editing `Pivots.md` or
  adding pivots in the Injestor updates host notes and the canvas without
  a full rebuild. Existing Injestor pages get the new section appended.

### Fixed

- **Injestor crashed on any paste with both a new IP and a hostname.**
  Creating the new host note searched for nearby hostnames in an undefined
  variable, raising `NameError` after the note was written but before the
  archive note, the credential write and the page reset, so the paste
  stayed in `Injestor.md` and hit the same crash the next time it was
  processed.

- **One incomplete scan file no longer aborts the whole run (and silently
  skips the canvases).** An interrupted Nmap scan (`-oA` killed partway, so
  the XML has no closing `</nmaprun>`) or a partial Nessus export raised
  `ParseError` straight out of `_run_processing`. Every scan file after it
  went unprocessed, and the end-of-run writes never happened: no Assessment
  Canvas, no Users Canvas, no Campaign Targets, no incremental state. It
  looked like "canvases aren't being generated." The Nmap and Nessus loops
  now log a warning and skip the unparseable file, matching the existing
  Burp/AutoRecon behaviour. The file is not marked analyzed, so it is picked
  up automatically once the scan finishes or the file is replaced.
- **Loot/Credentials.md table corruption on every Injestor append once a
  table had been reformatted** (e.g. by Obsidian's own table editor, which
  pads separator rows as `| --- |` instead of `|---|`). The parser only
  recognised the unpadded form, so a padded separator was misfiled as a data
  row on the next parse/rewrite and the Campaign-Level table lost its
  separator entirely. The parser now tolerates any padding/alignment, and
  the writer self-heals a table whose separator was already lost by an
  earlier run instead of re-emitting a broken table.
- **Kiwi/mimikatz/meterpreter pastes were attributed to the wrong host, or
  no host at all.** Injestor host-detection for the kiwi fast-path only
  looked for a literal IPv4 address in the pasted text — but mimikatz and
  meterpreter output identify the target by hostname
  (`Local name : HOST`, `Running module against HOST`), never by IP, so
  every such paste fell through to Campaign-Level. Host detection now also
  matches known vault host identifiers (IP/hostname/short-name) when no IP
  is present.
- **The lsa_dump_secrets parser recorded a secret's name as a username.**
  `Secret: DefaultPassword` / `cur/text: <value>` was previously written as
  username `DefaultPassword` — but that's the LSA secret's name, not an
  account, and this output format never reveals which account the decoded
  value belongs to. It's now recorded as `LSA Secret: DefaultPassword` with
  a note prompting manual correlation instead of a fabricated identity that
  silently discarded the real credential.
- **Found while verifying the fix above: any Injestor-added credential with
  no backing `scans/loot/` file was deleted by the very next run.**
  `_write_loot_credentials_page` fully rebuilds `Loot/Credentials.md` from a
  fresh loot-directory scan every time, so a row that only ever existed
  because Injestor added it (kiwi paste, LSA secret, `+cred`) had nothing to
  be re-derived from and silently vanished on the next batch run or
  `/refresh`. It now carries forward any row the fresh scan didn't reproduce
  instead of treating the loot directory as the sole source of truth.
- **A short, explicit credential line in `## Notes` was silently dropped.**
  Pasting e.g. `for CORP-WS03 administrator:HASH:CrackedPw123` into the
  templated `## Notes` section did nothing: that path only ever tried
  NXC/kiwi detection, then required 8+ non-IP words before even considering
  the LLM — a single precise credential line never reaches that. The
  deterministic parser (previously reachable only on old, template-less
  Injestor pages) now runs as a fast-path in both `## Notes` and `## Tool
  Output` regardless of length, gained a "for HOST user:pass" pattern (host
  stated first, not just `user:pass on HOST`), and now splits a
  `user:hash:crackedpassword` value into hash + cracked-password note.
- **Found while adding the fast-path above: any Injestor credential that
  resolved to a host crashed the run.** `_link_injestor_creds_to_host_note`
  called `split_frontmatter()`, a function that doesn't exist anywhere in
  this codebase — every credential where host attribution worked hit an
  unhandled `NameError` while updating that host's `## Loot` summary. Fixed
  to use `read_frontmatter`/`write_frontmatter`, the pattern already used
  everywhere else.
- **`/review` silently mislabeled hashes as cleartext passwords.** The
  credential-promotion path and the new re-extraction path above both feed
  `_append_injestor_to_credentials_md`, whose hash check only recognised the
  `<TYPE>_hash`/`hash` suffix convention — not the bare `NTLM`/`SHA1`/`bcrypt`
  names `_parse_pending_review_row` and `_classify_hash` produce. Any
  credential promoted via `/review` with a recognised hash type ended up in
  the Password column with empty Hash/Hash Type columns instead of being
  labeled as a hash.

### Changed

- **The canvas Next Steps panel now says how to fill it.** It used to read
  "Run scans with AI analysis enabled". It now lists the actual commands
  (`/analyze-full`, `/analyze`, `/deepdive`, `/refresh`, and
  `python mAIpper.py --reanalyze`), including the non-obvious part: scans
  first processed by `-i` or `--no-ollama` are marked done, so a plain
  batch run skips them.
- **Next Steps reads analysis already saved in scan notes**, not just
  analysis produced during the current batch run. Results from interactive
  `/analyze` previously never reached the panel, and a batch re-run with
  no changed scans reset it to the placeholder.
- **LLM analysis output is now much terser and command-first.** Reported
  feedback: per-port Deep Dive callouts and Loot analysis read like generic
  IT-textbook explanation ("this service allows X, which could expose Y")
  instead of actionable next steps. Every narrative prompt now instructs the
  model to skip explaining well-known services/protocols/tools, keep every
  bullet to one line, and omit a section rather than pad it — and
  `_Assessment Config.md`'s System Prompt (already prepended to every
  analysis call) carries the same policy, so it's the one place to further
  tune tone/verbosity without a code change. Deep Dive dropped from 5
  sections to 3 (Commands / Findings / Next Step) and Loot analysis from 3
  to 2 (Commands to Try / Notes), both leading with ready-to-run commands.

## v0.18

Reported bug: having a host note open in Obsidian while mAIpper runs crashed
the whole tool with an unhandled `PermissionError`.

### Fixed

- **A locked note file no longer crashes the run.** On Windows, another
  process holding a file open without `FILE_SHARE_DELETE` (Obsidian
  rendering the note, a search indexer, an antivirus scan, a sync client)
  makes `os.replace()` fail with `PermissionError` ([WinError 5]/[WinError
  32]) during the atomic write, even though nothing else is wrong.
  `_atomic_write_text()` now retries the replace step with backoff (~3.8s
  total) to ride out the common transient case, and raises a new
  `FileLockedError` — instead of a bare `PermissionError` — if the file is
  still locked afterward.
- **Locked files are skipped, not fatal.** Every per-host and per-scan-file
  write loop (Nmap, Nessus, Burp, AutoRecon, Loot, Misc, NXC, deep dives,
  canvases, Campaign Targets, PlexTrac export, incremental state) now catches
  `FileLockedError` at the smallest reasonable granularity — usually one host
  note — logs a warning, and moves on. Everything else in that run still
  gets written. Nothing is marked "analyzed" for a file whose write failed,
  so it's picked up automatically on the next run or watch cycle; no data is
  lost, only deferred until the file is closed.
- **Batch mode and interactive mode both have a last-resort catch** for any
  `FileLockedError` not individually handled above, printing an actionable
  message ("close the file and re-run") instead of a raw traceback.
- The small window between an editor reading the old note and mAIpper's
  `os.replace()` landing the new one is not otherwise a risk: `os.replace`
  is atomic on both platforms, so a reader always sees either the fully-old
  or fully-new file, never a partial write.

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
