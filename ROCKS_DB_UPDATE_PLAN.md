# Plan: Upgrade RocksDB 6.22.1 -> 10.6.2 in osquery

Audience: an implementing agent (and reviewers). Read the whole document before starting.
Every phase has an explicit **exit criterion**. Record all evidence (logs, numbers, scripts) in
`rocksdb-upgrade-evidence/` (do **not** commit it; attach summaries to the PR).

---

## 0. Scope, goals, non-goals

**In scope**
- Move the vendored RocksDB from `v6.22.1` (commit `51b540921dd7495c9cf2265eb58942dad1f2ef72`) to `v10.6.2`.
- Platforms: Linux x86_64, Linux aarch64 (osquery-toolchain), macOS x86_64, macOS arm64, Windows x86_64 (MSVC).
- Prove: builds cleanly, no functional regressions, no CPU/memory regression, rollback to the previous osquery
  release still works, and quantify the benefits (robustness, perf, resolved GitHub issues).

**Out of scope (explicit non-goals)**
- Anything above 10.6.x. RocksDB >= 10.7 requires C++20 (including for code that includes RocksDB headers) and a
  toolchain bump (osquery-toolchain 1.2.0 is clang 11; a bump is being worked on separately). Do not touch the
  toolchain or `cxx_std_17` in `cmake/flags.cmake`. RocksDB 10.6.2 is the latest release maintaining C++17 support.
- Turning on new RocksDB features (`wal_compression`, `track_and_verify_wals`, newer `format_version`, etc.).
  The first release must preserve on-disk compatibility with the previous osquery release.
- Changing the DB schema/domains, osquery's `database` plugin API, or any table behaviour.

**Justification being tested (the "why")** - the PR must show evidence for each, or say honestly that it found none:
1. Robustness of open/recovery/shutdown (fixes in 7.2-9.9, see section 9).
2. Performance (expected: parity, possibly small startup/compaction gains) - measured, not assumed.
3. Supportability/security posture (CVE scanner noise, upstream support).
4. Specific osquery GitHub issues that may be resolved (section 10).

---

## 1. Facts about the current integration (verified in the repo)

| Item | Location |
|---|---|
| Submodule | `.gitmodules` -> `libraries/cmake/source/rocksdb/src` (https://github.com/facebook/rocksdb) |
| Submodule import | `libraries/cmake/source/modules/Findrocksdb.cmake` (`importSourceSubmodule`, shallow) |
| Hand-maintained build | `libraries/cmake/source/rocksdb/CMakeLists.txt` (~505 lines, ~304 `.cc`/`.cpp` files listed manually, per-platform/arch `target_compile_definitions`, folly sources for non-macOS, crc32c SSE4.2/PCLMUL flags, PCH on non-Windows) |
| Generated version file | `libraries/cmake/source/rocksdb/version/build_version.cc` (hard-coded sha `51b540...`, tag `v6.22.1`, date) |
| PCH | `libraries/cmake/source/rocksdb/osquery_rocksdb_pch.h` |
| Windows patch | `libraries/cmake/source/rocksdb/patches/env_win.h` (force-included into `env_win.cc`; defines `_WIN32_WINNT_VISTA` so `AreFilesSame` returns NotSupported) |
| Build notes | `libraries/cmake/source/rocksdb/README.md` (upstream cmake flags per platform; Xcode 13 / SDK 11.3 paths are stale) |
| CVE manifest | `libraries/third_party_libraries_manifest.json` (`rocksdb`: version `6.22.1`, commit `51b540...`) - CI checks `commit` against the submodule; `version` is NOT checked (see `docs/wiki/development/cve-scan.md`) |
| Registration | root `CMakeLists.txt:117` (`"Linux,Darwin,Windows:rocksdb"`), `plugins/database/CMakeLists.txt` (`thirdparty_rocksdb`), `osquery/main/CMakeLists.txt`, `osquery/main/harnesses/CMakeLists.txt` |
| Plugin | `plugins/database/rocksdb.cpp`, `rocksdb.h`, tests `plugins/database/tests/rocksdb.cpp` |
| Buck codegen | `tools/codegen/gentargets.py:86` (`//rocksdb:rocksdb`) - check if anything is needed |
| Docs mentioning RocksDB | `docs/wiki/**`, `CHANGELOG.md`, `SECURITY.md`, `ASSURANCE.md` (mostly informational) |

Plugin behaviour that matters for this upgrade:
- `RocksDBDatabasePlugin::openDB()` already has a version guard (`ROCKSDB_MAJOR > 9 || (== 9 && MINOR >= 11)`) using the
  `std::unique_ptr<DB>` overload of `DB::Open`. With 10.6.2 this branch is taken. **Verify both branches compile and
  behave identically** (ownership: `db_ = db.release()`).
- Options set (rocksdb.cpp ~L105-135): `create_if_missing`, `create_missing_column_families`, `info_log_level=ERROR`,
  `log_file_time_to_roll=0`, `keep_log_file_num=10`, `max_log_file_size=1MiB`, `max_open_files=128`,
  `stats_dump_period_sec=0`, `max_manifest_file_size=500KiB`, `compression=kNoCompression`,
  `compaction_style=Level`, `arena_block_size=4KiB`, `write_buffer_size=4KiB*rocksdb_buffer_blocks(256)`,
  `max_write_buffer_number=rocksdb_write_buffer(16)`, `min_write_buffer_number_to_merge=rocksdb_merge_number(4)`,
  `max_background_flushes=rocksdb_background_flushes(4)`. **No `BlockBasedTableOptions` are set** -> format version and
  checksum type come from library defaults, which change between 6.22 and 10.6 (see section 4).
- Domains (column families): `configurations`, `queries`, `events`, `logs`, `carves` (+ `default`, plus unknown CFs
  found via `ListColumnFamilies` for rollback support).
- Startup does `compactFiles()` on every domain except `events` -> **every SST is rewritten on first start with the new
  library**, so rollback compatibility is determined by what the new library *writes*, not by what it can read.
- On `Status::IsCorruption()` at open or on close when the log callback saw `Corruption:`, the plugin calls `repairDB()`
  which moves the DB to `<path>.backup` and recreates it **empty** (node key, query baselines, unshipped events lost).
- Writes use `sync=false` for events/deletes (see `WriteOptions` in `rocksdb.cpp`).

---

## 2. Success criteria / go-no-go

All must be true to merge:

1. Clean configure+build on all 5 platform builds in CI; **warning/error delta** (section 5) reviewed and explained.
2. All existing unit + integration tests pass on all platforms (Debug and Release where CI runs both).
3. New tests added in section 6/7 pass; the cross-version compatibility matrix (section 7) passes in **both** directions
   (old->new and new->old) on at least Linux x86_64 and one of {macOS, Windows}, ideally all.
4. Crash/durability matrix (section 8) shows **no new failure** vs baseline and reproduces at least the reproducible
   upstream-fixed cases as failing on 6.22.1 and passing on 10.6.2 (or documents why not reproducible).
5. Perf: median CPU and RSS within **+5% CPU / +10% RSS** of baseline in every workload (section 11), no latency
   regression in DB open > 20%, DB directory size within +10%. Improvements are reported as measured.
6. ASAN + TSAN (+ LSAN where available) runs on Linux show no new reports attributable to RocksDB integration.
7. 72 h soak on at least one host per OS (section 12) with no crash, no `repairDB`, no unbounded growth.
8. Manifest/CHANGELOG/docs updated; PR template followed.

A hard **NO-GO** (stop and report): any DB corruption/data loss on 10.6.2 not seen on baseline; rollback test
failing without a viable option pin; CPU/RSS regression over thresholds that cannot be explained or tuned away.

---

## 3. Phase 0 - Baseline capture (do this BEFORE changing anything)

Create a worktree/branch of current `master` at the baseline commit; record `git rev-parse HEAD`.
Everything compared later is against this baseline, built with the **same** compiler/toolchain/flags/runner type.

### 3.1 Baseline builds
For each platform, build `RelWithDebInfo` (what ships), plus Debug+tests and Release+tests where CI does. Save:
- Full configure + build logs (`cmake --build ... -v` where practical, with `-DCMAKE_VERBOSE_MAKEFILE=ON`).
- Wall-clock build time of `thirdparty_rocksdb` target alone (`cmake --build . --target thirdparty_rocksdb`, clean).
- Size of `libthirdparty_rocksdb.a` / `.lib`, and of final `osqueryd` and `osqueryi` (stripped and unstripped).
- Compiler warnings count for the `thirdparty_rocksdb` target and for `plugins_database_rocksdbplugin` (script in 5.1).

### 3.2 Baseline artifacts for compatibility testing
Keep the baseline `osqueryd`/`osqueryi` binaries (these are the "old" binaries used for upgrade/rollback tests).
Also build a tiny standalone driver (section 6.1) against **6.22.1** and keep it.

Create reusable DB fixtures with the **baseline** binary under `fixtures/`:
- `fresh/` - created by starting and cleanly stopping osqueryd once.
- `busy/` - ran 24 h (or accelerated: 1 s schedules + event flood) so that all domains have data, multiple SSTs and
  multiple MANIFEST rotations (`max_manifest_file_size` is 500 KiB, so force rotations).
- `large/` - >= 1M keys, >= 500 MiB of `queries`+`events` data, many levels.
- `unclean/` - baseline killed with SIGKILL mid-write (several variants, section 8).
- `corrupt-*/` - hand-damaged copies (section 8).
- `future-cf/` - has an extra unknown column family (osquery rollback case).
Record checksums and file listings (`ls -la`, `OPTIONS-*`, `MANIFEST-*`, `CURRENT`, `IDENTITY`) for each.

### 3.3 Baseline performance numbers
Run every workload in section 11 against the baseline and store raw results. Without this the comparison is meaningless.

**Exit criterion:** baseline binaries, fixtures, build logs and perf numbers archived and reproducible by script.

---

## 4. Phase 1 - Mechanical upgrade

Use one branch (`rocksdb-10.6.2`). Commit in reviewable steps.

### 4.1 Submodule bump
```
git -C libraries/cmake/source/rocksdb/src fetch --tags    # after `git submodule update --init` for that path
git -C libraries/cmake/source/rocksdb/src checkout v10.6.2
git add libraries/cmake/source/rocksdb/src
```
Record the exact commit of `v10.6.2` (`git rev-parse HEAD` inside the submodule). Do NOT use a tag SHA from a different
fork. Confirm `.gitmodules` URL is unchanged.

### 4.2 Source list reconciliation (`libraries/cmake/source/rocksdb/CMakeLists.txt`)
Upstream's source list is the `SOURCES` set in upstream `CMakeLists.txt`. Preliminary comparison (6.22.1 list vs
v10.6.2 list, versus ours): Do it programmatically and keep the script in evidence:
1. Extract `set(SOURCES ...)` from upstream `CMakeLists.txt` at v10.6.2.
2. Extract our list (`grep -o 'library_root}/[^"]*\.\(cc\|cpp\)'`).
3. Produce add/remove lists; then review every entry by hand.
4. Decide per file whether osquery needs it. Default: **match upstream's list** (link whole upstream library) except for
   things upstream makes conditional (jemalloc, snappy/lz4/zstd/zlib/bz2, uring, gflags, tools, tests, benchmarks,
   `*_test*.cc`, `*_bench*.cc`, `*_stress*.cc`, `db_stress_tool`, `tools/*`, `java/*`). Document each exclusion.
5. Verify no unintended test/tool files are compiled (`grep -E '(_test|_bench|stress|tool)'` on the final list).

### 4.3 Compile definitions / flags
Diff upstream's `CMakeLists.txt` + `cmake/modules/*` + `build_tools/build_detect_platform` between v6.22.1 and v10.6.2
for: new `add_definitions`/`target_compile_definitions`, new `HAVE_*` probes, `ROCKSDB_*` feature macros, `-D` per OS,
`ROCKSDB_NAMESPACE`, Windows definitions, arm64 CRC (`HAVE_ARM64_CRC`, `-march=armv8-a+crc`), `HAVE_UINT128_EXTENSION`,
`HAVE_FULLFSYNC` (macOS), `ROCKSDB_LIB_IO_POSIX`, `OS_*`, thread-local support, `ROCKSDB_NO_DYNAMIC_EXTENSION`,
`NPERF_CONTEXT` / `NIOSTATS_CONTEXT`. Update our per-platform/arch blocks accordingly. Each change needs a one-line
comment in the PR description (not code comments) explaining its upstream origin.
- Keep the current feature disables from `README.md`: no gflags, no tools, no liburing, no compression libs,
  `PORTABLE=ON`, `FORCE_SSE42` semantics on x86_64 (see issue #8058 about SSE4.2 requirements - section 10 & 13).
- Check the crc32c file set: in 10.x `util/crc32c.cc` still holds SSE4.2/PCLMUL paths; confirm the `COMPILE_FLAGS`
  property still applies to the right file(s) and that `-msse4.2 -mpclmul` + runtime dispatch (`isSSE42()`/
  `isPCLMULQDQ()` via cpuid) is what upstream does now.
- Re-check includes: upstream added `include/rocksdb/*` new headers; keep the SYSTEM
  INTERFACE include dir.

### 4.4 Other repo files
- `version/build_version.cc`: regenerate for v10.6.2 (use upstream `build_tools/gen_build_version.sh` or the
  CMake `build_version.cc.in` equivalent to see the expected shape; the file layout changed since 6.22 - e.g. new
  property lists). Set git sha, tag `v10.6.2`, and commit date. Do not hand-edit stale content.
- `patches/env_win.h`: inspect upstream `port/win/env_win.cc` / `env_win.h` for `AreFilesSame` and `_WIN32_WINNT`
  use at v10.6.2. Either keep, adapt, or delete the patch + CMake property; justify the decision in the PR. Confirm the
  project-wide `_WIN32_WINNT` (see `cmake/flags.cmake`) is still honoured (Windows 7 floor today).
- `osquery_rocksdb_pch.h`: update includes to headers that still exist; make sure PCH still skips crc32c via
  `SKIP_PRECOMPILE_HEADERS`. Update the "303 source files" comment in CMakeLists if the count changes (comment text only).
- `libraries/third_party_libraries_manifest.json`: set `"version": "10.6.2"` and `"commit"` to the submodule commit.
  Run `tools/ci/scripts/cve/validate_manifest_libraries_versions.py` as CI does (read `cve_scan_runner.yml`).
  **Double-check `version` manually** - CI does not.
- `libraries/cmake/source/rocksdb/README.md`: refresh the upstream cmake flag lists (generate them from the upstream
  10.6.2 options; replace stale Xcode 13 / SDK 11.3 text with current guidance).
- `tools/codegen/gentargets.py`: confirm nothing depends on the old file list.
- `CHANGELOG.md`: do not edit unless contributors normally do so for libs updates (check git history); the maintainers
  usually generate it at release time.

### 4.5 Pin on-disk format for rollback safety (plugin change - small)
Problem: defaults changed since 6.22.1 and old osquery cannot read some new defaults:
- Default checksum became `kXXH3` in 7.8 (readable only by RocksDB >= 6.27, i.e. **not** 6.22.1).
- Default `BlockBasedTableOptions::format_version` became 6 in 9.0 (not readable by < 8.6.0).
- `write_dbid_to_manifest` became true by default in 9.7 (MANIFEST/IDENTITY handling; verify old reader tolerance).

Required work:
1. In the **6.22.1** source determine the exact defaults: `BlockBasedTableOptions::format_version`, `checksum`,
   `filter_policy` (none?), `index_type`, `whole_key_filtering`, `cache_index_and_filter_blocks`, `block_cache`
   (default 32 MiB -> 8 MiB in newer versions? verify), `block_size`, `block_restart_interval`, `partition_filters`,
   `pin_*`, etc. Record them in a table (old default vs new default).
2. Also diff `DBOptions`/`ColumnFamilyOptions`/`AdvancedColumnFamilyOptions` defaults between the two tags
   (`include/rocksdb/options.h`, `advanced_options.h`, `table.h`). List every changed default and classify:
   (a) irrelevant, (b) behaviour/perf relevant to osquery, (c) on-disk-compat relevant. Review each (b)/(c) in the PR.
3. In `RocksDBDatabasePlugin::setUp()` set an explicit `BlockBasedTableOptions` and
   `options_.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_options))` pinning **exactly the 6.22.1
   effective values for everything that affects on-disk format**: at least `format_version` and `checksum`
   (`kCRC32c`). For **memory/perf-affecting** defaults (e.g. block cache size, filter/index caching), pin the old
   values too **unless** the benchmarking in section 11 justifies something else - the goal of this PR is "no
   behavioural change", not tuning.
4. Make the pin overridable for testing via a hidden flag ONLY IF needed for the compatibility experiments (e.g.
   `--rocksdb_format_pin=false`); otherwise do not add flags. Prefer a build-time test hook.
5. Keep the version guard in `openDB()`. Confirm `ROCKSDB_MAJOR/MINOR` macros come from `rocksdb/version.h` at 9.11.2.
6. Keep all other plugin behaviour unchanged. Fix compile errors only; do **not** refactor.

Decision gate: if pinning is impossible or rollback fails even with pins, STOP and report (go/no-go 2).

**Exit criterion of Phase 1:** branch builds locally on Linux x86_64 (osquery-toolchain) with `OSQUERY_BUILD_TESTS=ON`
and the rocksdb plugin tests pass. Then push to CI for the other platforms.

---

## 5. Phase 2 - Build log analysis (errors and warnings)

Goal: answer "does the new version introduce or remove errors/warnings, and what changed in build cost?"

### 5.1 Method
Use identical flags/compilers for baseline vs candidate. For every platform:
1. Capture full verbose logs for a clean build of `thirdparty_rocksdb` and of `plugins_database_rocksdbplugin` (+ tests).
2. Normalise and count: clang/gcc `warning: ... [-W...]`, MSVC `warning C####`, linker warnings, deprecation warnings,
   per-file. Script: parse logs -> CSV (`file, flag/code, message`) -> diff baseline vs candidate:
   - new warnings (candidate only), removed warnings (baseline only), unchanged.
   - Separate **RocksDB internal files** from **osquery files that include RocksDB headers**
     (`plugins/database/rocksdb.cpp`, tests, `osquery/...` files that include `<rocksdb/...>`; e.g. `osquery/core/query.h`,
     `osquery/database/database.cpp`, `plugins/logger/buffered.cpp`, `osquery/events/benchmarks/...`).
   - Check that osquery's own targets compile with `-Werror`-equivalent settings (project uses `/WX` / `-Werror` in
     osquery-owned targets; confirm in `cmake/flags.cmake`): new header warnings in rocksdb includes would break them.
     RocksDB include dir is `SYSTEM INTERFACE`; verify it is still treated as a system include on MSVC (`/external:I`?)
     so header warnings are suppressed.
3. Compare also: static analysis (`cppcheck` target in CI, `clang-tidy` if enabled) - 3rd party excluded but plugin
   included.
4. Compare: build time, object count, `.a/.lib` size, final binary size (+ stripped), link time, PCH effectiveness.
5. Check that `-fno-pch-timestamp`/PCH settings still produce reproducible builds (build twice, compare hashes where
   osquery claims reproducibility).

### 5.2 Report table (fill in, per platform)
| Metric | Baseline | Candidate | Delta | Notes |
|---|---|---|---|---|
| Warnings in thirdparty_rocksdb | | | | |
| Warnings in osquery files incl. rocksdb headers | | | | |
| Errors | | | | |
| rocksdb lib size | | | | |
| osqueryd size (stripped) | | | | |
| Clean build time of target | | | | |

Explain every **new** warning class; either suppress locally in the rocksdb target (never globally), or fix upstream-
compatible. Do not patch RocksDB sources unless unavoidable; if a source patch is unavoidable, store it as a numbered
`.patch` file next to `patches/env_win.h` and apply via CMake - never edit the submodule worktree.

**Exit criterion:** table complete; zero new errors; every new warning triaged.

---

## 6. Phase 3 - Functional testing

### 6.1 Existing tests (must pass on every platform)
- `plugins/database/tests/rocksdb.cpp` (log level, forwarding, etc.).
- `osquery/database/tests/*` (database.cpp, results.cpp), `osquery/events/tests/*`, `osquery/tables/events/tests/*`,
  config, logger (`buffered`), `osquery/core/tests`, enroll tests - everything that touches the database. Run the whole
  suite: `ctest -N` to enumerate, then `ctest --output-on-failure` (follow `.github/workflows/hosted_runners.yml`
  for the exact invocation incl. the "root tests" variant).
- Python integration tests in `tools/tests/` (`test_osqueryi.py`, `test_osqueryd.py`, `test_extensions.py`,
  `test_additional.py`, `test_query_packs.py`, `test_http_server*.py`, Windows: `test_windows_service.py`). Run on each OS.
- `osquery/events/benchmarks/events_benchmarks.cpp` (Google Benchmark) - these double as perf data (section 11).

### 6.2 New tests to add (small, in existing test files where possible)
Add to `plugins/database/tests/rocksdb.cpp` (or `osquery/database/tests`):
1. **Open/close cycles:** 1,000 open/close loops, asserting no leaked FDs (Linux: count `/proc/self/fd`) and clean state.
2. **Unknown column family on open** (rollback support): create DB with extra CF, reopen with plugin, verify it opens
   and the extra CF data survives.
3. **Domain isolation**: same key in each domain does not collide; `scan` prefix semantics unchanged; `getKeys`
   ordering unchanged (iterator order is by bytewise comparator; assert on a fixed sample).
4. **Batch semantics:** `Write` batches (`putBatch`) atomicity; delete range via `removeRange`/`scan+delete` semantics
   match baseline for events expiry usage.
5. **Corruption path:** truncated `IDENTITY`, zero-length `CURRENT`, truncated last `MANIFEST`, damaged WAL tail ->
   plugin either opens or goes through `repairDB()` as before; assert resulting behaviour is **no worse** than
   baseline (see section 8 for the baseline-vs-candidate comparison).
6. **Option pin test:** open the DB, read the table properties (`GetPropertiesOfAllTables`) and assert
   `format_version` and `checksum_type`/`compression_name` equal the pinned values; assert OPTIONS file content
   contains the pinned values. This protects rollback compatibility against future silent default changes.
7. **Version guard test:** a `static_assert`/test that `ROCKSDB_MAJOR`/`MINOR` match the manifest version
   (prevents manifest drift, which CI does not check).

Standalone driver (not committed, kept in evidence, built against both RocksDB versions): small C++ program that opens
the DB exactly like the plugin (same options) with a CLI for `put/get/scan/delete/compact/dump-properties`. Used for
sections 7/8 where the full osqueryd is overkill and for scripting crash loops. Build it twice (6.22.1 and 9.11.2).

### 6.3 Platform-specific functional checks
- **Windows:** DB path with spaces and non-ASCII; `database_path` on a different drive; permission hardening
  (`platformSetSafeDbPerms`) still produces expected ACLs; service start/stop/restart loop; AV/indexer interference not
  tested but note sharing violations in logs; `AreFilesSame` behaviour (patch) - exercise paths that call it
  (e.g. `CreateColumnFamily`/`LinkFile`/`RenameFile` in recovery) via crash-recovery test; long paths (>260).
- **macOS:** `F_FULLFSYNC` behaviour irrelevant (we do not sync) but check `OS_MACOSX` defines; SIP/TCC not relevant;
  arm64 **without** SSE4.2 define; run natively on Apple Silicon; check Rosetta x86_64 build starts.
- **Linux:** x86_64 and aarch64; glibc old-system compatibility of resulting binary (toolchain builds against old glibc -
  verify symbols with `objdump -T | grep GLIBC_` that the max required version did not increase; new RocksDB code
  may reference newer libc APIs such as `fallocate`/`sched_getcpu`/`pthread_*` variants); non-ext4 filesystems
  (xfs, btrfs, overlayfs in containers, tmpfs, NFS if supported); read-only DB dir; `max_open_files=128` with low
  `ulimit -n`.

**Exit criterion:** green on all platforms; new tests merged into suite.

---

## 7. Phase 4 - Upgrade / downgrade (rollback) compatibility matrix

This is the highest-risk area. RocksDB has no migration step: new code opens old files; compaction at osquery start
rewrites all non-events SSTs in the new library's format; MANIFEST/OPTIONS are rewritten on open.

### 7.1 Matrix (run each cell on Linux x86_64 first, then on macOS and Windows)
Binaries: `OLD` = baseline osquery (6.22.1), `NEW` = candidate (9.11.2 with pins), `NEW-nopin` = candidate built
*without* the format pin (negative control to prove the problem exists and the pin fixes it).

| # | Start DB | Run | Then run | Expected |
|---|---|---|---|---|
| U1 | fresh by OLD | NEW | - | opens, data intact |
| U2 | busy by OLD | NEW | - | opens, all keys identical (checksum of dump) |
| U3 | large by OLD | NEW | - | opens; measure open time + first-start compaction time |
| U4 | unclean by OLD (SIGKILL) | NEW | - | recovers; compare lost-write window vs OLD recovering its own |
| U5 | future-cf by OLD | NEW | - | opens (unknown CF retained) |
| R1 | fresh by NEW | OLD | - | **opens without repairDB**, data intact |
| R2 | busy by OLD -> NEW (compacted) | OLD | - | opens, data intact, no `Corruption` in logs |
| R3 | R2 DB, NEW wrote more data (flushes+compactions+MANIFEST rotations) | OLD | - | opens, all data intact |
| R4 | busy by NEW | OLD | NEW | round trip OK |
| R5 | R3 but killed -9 while NEW running | OLD | - | recovers like OLD would from its own crash |
| R6 | repeat U1-U4 and R1-R5 using `NEW-nopin` | OLD | - | **expected to FAIL** (proves test sensitivity) |
| M1 | A->B->A->B ping-pong x 20, random SIGKILL in between | OLD/NEW alternating | - | never corrupt, never `repairDB` |

For every cell record: exit status, `Corruption`/`repairDB` log lines (check `<db>.backup` was NOT created), key-by-key
dump equality (`scan` of all domains via the standalone driver, compare SHA-256), `OPTIONS-*`/`CURRENT`/`IDENTITY`
files, SST table properties (format_version, checksum, compression).

### 7.2 Also verify
- `OLD` can **read** NEW-written SSTs not only open them: force reads after R-cells (full scan of every domain).
- `ldb`/`sst_dump` from the 6.22.1 and 10.6.2 builds (build once, outside the product) to dump properties of
  SST/MANIFEST/WAL for evidence. Build tools only in evidence; never ship.
- Two different NEW binaries (10.6.2 now vs a later 10.6.x) are compatible.
- osquery's own multi-process behaviour: `osqueryd` watcher + worker + `osqueryi` simultaneously on the same DB path
  (osqueryi uses an ephemeral DB by default; test `--database_path` shared cases and the lock error path:
  "IO error: lock hold by current process"/`LOCK` file semantics on Windows vs POSIX).
- If anything in R-cells fails even with pins, inspect which new MANIFEST tags / OPTIONS properties the old reader
  chokes on (use `ldb manifest_dump` of both) and, if needed, set the corresponding option off (candidates:
  `write_dbid_to_manifest=false`, `write_identity_file=true`, `verify_sst_unique_id_in_manifest`, new file-checksum/
  `write_dbid` behaviours, `track_and_verify_wals_in_manifest` stays false). Document each pin with the upstream
  HISTORY.md entry that motivated it.

**Fallback decision** (only if rollback cannot be made safe): document in release notes that downgrading wipes the local
DB (re-enrol/re-baseline) and get an explicit maintainer decision. Do not ship silently.

**Exit criterion:** all U/R/M cells pass with pins; R6 demonstrates failure without pins; evidence archived.

---

## 8. Phase 5 - Durability, corruption and crash-recovery testing

Goal: answer "can we reproduce DB corruption edge cases that 10.6.2 resolves?" and "is anything worse?".
Run **every** scenario on both OLD (6.22.1) and NEW (10.6.2, pinned) using the standalone driver and osqueryd.
Record the outcome table (pass/fail/behaviour) for both.

### 8.1 Reproducible upstream-fixed cases (try to show OLD fails, NEW passes)
| Upstream fix (HISTORY.md) | How to reproduce | Reachable by osquery? |
|---|---|---|
| 7.4: crash when `IDENTITY` is empty/truncated | Create DB, close, `truncate -s 0 IDENTITY`, open | Yes - easy |
| 7.2/7.4: `DB::Open` writes two new MANIFESTs before recovery succeeds | Damage the WAL tail so recovery fails/retries; or kill during recovery; inspect `MANIFEST-*` count and `CURRENT` | Yes |
| 9.5: MANIFEST write error deletes latest valid MANIFEST -> DB unopenable | Fault injection on MANIFEST write/sync (ENOSPC/EIO): small tmpfs/loop mount that fills up (disk-full), LD_PRELOAD shim failing `write/fsync` on `MANIFEST-*`; Windows: small VHD | Yes (disk full is realistic; see issue #8669 about disk usage) |
| 7.7: `CURRENT` directory not fsynced after update | Power-loss emulation (8.3) - may not reproduce on OLD deterministically; report as "not reproduced" if so | Yes (hard to show) |
| 7.6: fsync skipped after `DropColumnFamily` | osquery never calls `DropColumnFamily` -> **do not spend time**; mark not reachable | No |
| 7.1/7.2/6.24: DropColumnFamily/ColumnFamilyData races | same - not reachable | No |
| 8.4: `Env::Default()` used during static destruction | Start/stop osqueryd/osqueryi 10,000 times under ASAN; run `osqueryi -c "select 1;"` loops; watch exit crashes/ASAN reports; check core dumps | Yes (shutdown) |
| 9.9: leaked SST file handles until close | Long churn (write/flush/compact failures + writes); sample open FD count (`lsof -p`/`/proc/pid/fd`/Windows handle count via `handle64`/PerfMon) over hours | Yes |
| 6.25-6.29 `DumpStats`/`SstFileManager`/`CompactRange` races | `stats_dump_period_sec=0` so `DumpStats` n/a; `CompactRange` is called at startup - run TSAN with concurrent writer threads during startup compaction | Partially |
| 7.3: `avoid_flush_during_recovery`-related WAL removal corruption | not set by osquery -> not reachable; mark | No |
| 7.5/7.8: compaction behaviours | functional effect only; measured in perf | n/a |
| 9.11: `SetOptions` fix | osquery does not call `SetOptions` -> not reachable | No |

For each "Yes" row, produce: reproduction script, OLD result, NEW result, and a log excerpt. Unsuccessful reproductions
are still valuable - report them honestly ("could not reproduce on OLD").

### 8.2 Generic corruption injection (OLD vs NEW behaviour; must not regress)
For each fixture, apply and attempt `osqueryd --database_path`, `osqueryi --database_path`, then check whether
`<db>.backup` appears (meaning `repairDB()` wiped the DB):
- zero-length / missing / garbage `CURRENT`; `CURRENT` pointing at a missing MANIFEST;
- truncated and bit-flipped latest `MANIFEST-*` (head, middle, tail);
- missing SST referenced by MANIFEST; extra SST not referenced; bit-flip inside an SST data block, index block,
  footer; swapped SSTs (unique-ID verification in newer versions should catch it);
- truncated / bit-flipped / zeroed WAL (`*.log`) tail and middle;
- zero-length `OPTIONS-*`; missing `LOCK`; `LOG` file huge; permissions `000` on files; read-only DB directory;
- disk full during flush / compaction / MANIFEST rewrite / WAL append;
- directory moved while running (Windows sharing-violation behaviour).
Report: opened normally / auto-repaired (data kept) / repairDB wipe / crash / hang. The goal is **NEW is never worse
than OLD**, and the number of "wipes" is lower or equal.

### 8.3 Crash / power-loss loops
- **SIGKILL loop:** driver or osqueryd under a workload writing known deterministic data (`sequence number -> value`,
  separate counter written last); kill -9 at random times (uniform 10-5000 ms); reopen; verify: DB opens, no
  `repairDB`, written-and-synced data present, prefix property for unsynced writes holds (no holes within a domain for a
  single writer), counters monotonic. >= 10,000 iterations per version per platform (Windows: `taskkill /F`).
- **Snapshot-copy crash states:** while the workload runs, copy the DB directory at random instants (as a stand-in for an
  unclean shutdown) and test each copy opens - cheap approximation of crash-consistency.
- **True power-loss emulation (Linux):** `dm-log-writes` / `dm-flakey`, or a VM (QEMU) with `qemu` snapshot kill; or
  `LD_PRELOAD` fsync/rename-dropping shim (`libeatmydata` in reverse). Replay writes to arbitrary points and verify open.
  Prioritise rename/dir-fsync semantics (CURRENT updates).
- **Disk-full loop:** loop-mounted tiny FS; workload until ENOSPC; free space; verify recovery without wipe; repeat 1,000x.
- **Slow/failing disk:** `dm-delay` / throttled cgroup `io.max`; verify write stalls do not deadlock (cf. issue #5162
  "Stalling writes because we have 15 immutable memtables").

### 8.4 Evidence format
One table per platform: scenario x {OLD, NEW} x {open ok, data loss?, repairDB?, crash?, hang?, time to open}.

**Exit criterion:** NEW >= OLD in every row; list of reproduced-fixed bugs (at least the IDENTITY/MANIFEST ones, or an
honest explanation).

---

## 9. Phase 6 - Evented tables and differential stress testing

Evented tables (`process_events`, `file_events`, `socket_events`, `user_events`, `hardware_events`, `windows_events`,
`syslog`, etc.) write bursts into the `events` domain, index/expire via `events_expiry`/`events_max`, and read through
the DB scan APIs; differentials store the previous result set in the `queries` domain and compare on each run.
Both sit directly on the database plugin, so they are the most osquery-relevant stress targets.

### 9.1 Unit/in-process load tests (no OS event source needed)
Write a gtest or standalone harness (reusing `osquery/events/tests/mockedosquerydatabase.*`, `test_util`,
`EventSubscriberPlugin` test subclasses):
1. **Generator:** N threads add events with deterministic content (`id`, `time`, payload sizes 100 B / 1 KiB / 64 KiB)
   at configurable rate (1k, 10k, 50k events/s) for M minutes through `EventSubscriberPlugin::add`.
2. **Concurrent readers:** `generateRows`/`SELECT` via `osquery::SQL` over the event table with
   `time >= x AND time < y` constraints, while expiry (`expireEvents`, `expireCheck`) and `events_optimize` index
   paths run.
3. **Oracle:** keep an in-memory model; after each phase compare: total events = added - expired, no duplicates, no
   gaps, ordering by time, each event exactly once per differential, `events_max` honoured.
4. Run in a loop with **forced** DB close/reopen (`tearDown/setUp`) mid-flight and with injected `SIGKILL` of a child
   process hosting the DB; reopen and verify no lost *committed* events and no partial batches (WriteBatch atomicity).
5. Pathological shapes: single event of 10 MB; 1M tiny events in one second; many distinct event types (many key
   prefixes); keys at `events_expiry` boundaries; time going backwards (clock jumps); expiry of everything at once
   (large range delete).

### 9.2 Real osqueryd end-to-end
Config enabling events (`--disable_events=false`, `--disable_audit=false` on Linux where possible, file_paths
for `file_events`, etc.) with schedules at 1 s intervals including **differential** and **snapshot** queries and
`--logger_plugin=filesystem` (plus `tls` against the local test server in `tools/tests/test_http_server.py` for the
buffered logger path in `plugins/logger/buffered.cpp`, which uses the database for the unsent-log queue).
- Event sources to flood: Linux - `file_events` via inotify on a dir with a churn script (create/modify/delete 5k
  files/s), `process_events` via `bpf`/audit if available (exec storm: `for i in 1..N; do /bin/true; done` in parallel),
  `socket_events`; macOS - `file_events` via FSEvents, `process_events`/`es_process_events` via Endpoint Security if
  entitlements allow (otherwise `file_events` + `process_file_events`); Windows - `ntfs_journal_events`, `windows_events`
  (write to event log via `eventcreate` / PowerShell `Write-EventLog` storm) and `process_etw_events`/`file_events` where
  supported. Document which sources could not be run per platform.
- **Ground truth:** the churn script writes a manifest of what it did (path, op, timestamp); after the run, compare with
  rows returned and logged (allow documented loss only if the OS event source drops events - compare **OLD vs NEW**
  counts under identical load, they must match within noise, and NEW must never lose events that OLD kept).
- **Differential correctness:** a scheduled query over a controlled table (`file` over a dir the script mutates, or an
  extension table that returns scripted rows) with `differential`/`removed`/`added` logging; compare the log stream
  against ground truth: every add and remove observed exactly once, no spurious re-adds after restart. Test across
  **restarts** and **crash restarts** (differential baseline lives in the `queries` domain - this is where DB
  corruption/rollback would show up as spurious full-resultset "added" storms).
- Repeat with `--events_optimize=true/false`, `--events_expiry` small/large, `--events_max` small/large, and with
  `--database_path` on slow disk.
- Related existing issues to retest for regressions/improvements: #8531 (mac event expiration DB error),
  #8744 (differential "removed" events contain current values instead of cached), #8611 (counter resets on config
  purge), #5605 (events lost with `events_optimize` multiple constraints), #7079 / #8669 (DB growth / SST rotation).

### 9.3 Chaos during load
While 9.2 runs: kill -9 the worker (watcher restarts it); `SIGSTOP/SIGCONT`; low memory cgroup (`memory.max`) to
trigger watchdog kills (cf. #8806 unbounded memory growth); full disk; clock jump; suspend/resume (VM snapshot);
rapid config reloads (`config_refresh`); extensions connecting/disconnecting.

**Exit criterion:** zero event loss/duplication difference between OLD and NEW; differentials identical; no
`repairDB`; no stalls longer than OLD.

---

## 10. Phase 7 - GitHub issue triage ("do any issues resolve?")

Search results so far (`gh search issues --repo osquery/osquery rocksdb`) - candidates to evaluate, with the hypothesis
and test. Verify each by reading the issue, reproducing on OLD if possible, then re-running on NEW. Don't claim
"fixes" unless reproduced; otherwise label "possibly related / not reproduced".

| Issue | Title | Hypothesis | How to test |
|---|---|---|---|
| #8058 | Update RocksDB and remove SSE4 requirement to avoid Illegal Instruction crash on older CPUs | Newer RocksDB has runtime dispatch (`isSSE42`/cpuid) for crc32c; our `FORCE_SSE42`/`-msse4.2` + `HAVE_SSE42` may still crash if non-dispatched code uses SSE4.2 | Run NEW on a CPU without SSE4.2 (QEMU `-cpu qemu64`, `-cpu Nehalem` vs `-cpu core2duo`; or `valgrind`/Intel SDE `-p4p`) -> determine if the crash persists; try making SSE4.2 a runtime-detected path |
| #7884 | RocksDB ERROR when BPF is on | log/IO error under heavy event load | reproduce with BPF events flood, compare logs |
| #8531 | Mac Event Expiration Database Error | expiry path error | follow issue steps on macOS; compare OLD/NEW |
| #8669 | sst files rotation causes unexpected disk usage | compaction/obsolete file deletion (7.3 reduced mutex hold, 9.9 handle leaks, newer deletion scheduling) | measure DB dir size/file count over time under workload OLD vs NEW |
| #7079 | Severe disk impact and IOPS usage due to Database unexpected growth | same | same, plus IOPS (`iostat`/`pidstat -d`) |
| #5162 | Stalling writes because we have 15 immutable memtables | write stalls | stress with high write rate and measure stall log lines/latency |
| #8806 | Worker process unbounded memory growth leading to repeated watchdog kills | rocksdb memory (memtables/block cache) vs. osquery | RSS time series OLD vs NEW under the reporter's workload; heap profile (jemalloc not used; use `heaptrack`/ASAN LSAN) |
| #8644 | osquery fails to start on UDR7 (Debian 11 ARM64) | aarch64 CRC/IO defines | test aarch64 build on older kernels/glibc/QEMU |
| #4837 | RocksDB column families are off by one | plugin logic | check if still applicable (not RocksDB-version related) |
| #7239 | Update rocksdb to build natively on Apple Silicon | already done; regression check | build native arm64 mac |
| #7476/#8064/#5494 | watchdog/logger issues touching DB | indirect | note only |

Also run: `gh search issues --repo osquery/osquery "corruption" ...`, `"repairDB"`, `"database is locked"`,
`"IO error"`, `"LOCK"`, `"MANIFEST"`, `"Corruption:"`, `"leveldb"/"rocksdb" "windows"` and triage for anything
reproducible. Optionally scan upstream facebook/rocksdb issues for crashes referencing 6.x versions.

Deliverable: a table `issue -> reproduced on OLD? -> NEW result -> conclusion`. Only list "resolved by upgrade" for
reproduced-and-fixed cases; link the PR to issues only if the maintainers agree.

---

## 11. Phase 8 - CPU, memory, disk and latency measurement

Rules: same hardware/VM type, same OS image, same toolchain, same config; pin CPU governor; disable noisy neighbours;
repeat **>= 10 runs per cell**; randomize order of OLD/NEW; report median, p95, and a Mann-Whitney U (or bootstrap CI)
p-value; discard nothing silently. Warm and cold cache variants where relevant. Use `RelWithDebInfo` (shipping) binaries.

### 11.1 Workloads
| ID | Workload | Duration |
|---|---|---|
| W1 | **Idle daemon**: default-ish config, no schedule, events disabled | 30 min |
| W2 | **Typical fleet config**: 20 scheduled queries (mix of 10 s-1 h), differentials, `filesystem` logger | 2 h |
| W3 | **Aggressive schedule**: 50 queries at 1 s, differential results on a table returning ~5k rows | 1 h |
| W4 | **Event flood**: section 9.2 sources at max rate | 1 h |
| W5 | **TLS logger with offline server** (buffered logger fills DB queue then drains) | 1 h |
| W6 | **Large DB**: `large/` fixture; open + run W2 | 1 h |
| W7 | **Restart churn**: start/stop osqueryd every 5 s | 500 restarts |
| W8 | **Plugin micro-benchmark**: standalone driver, put/get/scan/delete/batch at 1/10/100 threads, 100 B/1 KiB/64 KiB values, sync=false, per domain | each op 5 min |
| W9 | **Existing benchmarks**: `events_benchmarks` (Google Benchmark `--benchmark_repetitions=20`) | n/a |
| W10 | **Startup latency**: time from exec to "database ready" and to first scheduled query; `osqueryi "select 1;"` wall time (ephemeral DB open/close) | 200 runs |
| W11 | **First-start-after-upgrade**: `busy/` and `large/` DB opened by NEW for the first time (one-time compaction rewrite) | 10 runs |

### 11.2 Metrics and tools
- **CPU:** user+sys CPU seconds and % per process (watcher, worker); Linux `pidstat -u -p`, `/usr/bin/time -v`,
  `perf stat` (cycles/instructions, context switches), `perf record` flame graphs for W3/W4/W8 (look at rocksdb frames:
  `crc32c`, `memtable`, `compaction`, `LRUCache`, mutex); macOS `top -l`, `ps`, `sample`/Instruments Time Profiler;
  Windows PerfMon (`Process\% Processor Time`), WPR/WPA, `typeperf`.
- **Memory:** RSS and PSS time series every 1-5 s (Linux `smem`/`/proc/pid/smaps_rollup`; macOS `footprint`, `vmmap
  -summary`; Windows `Working Set`/`Private Bytes`/commit via PerfMon). Peak and steady-state; slope over time (leak
  detection: linear fit on W2/W4 after warm-up). `heaptrack` or `valgrind --tool=massif` on Linux for allocation
  breakdown (memtables vs block cache vs index/filter vs internal). Optionally query RocksDB properties via the driver
  (`rocksdb.estimate-table-readers-mem`, `rocksdb.cur-size-all-mem-tables`, `rocksdb.block-cache-usage`,
  `rocksdb.estimate-num-keys`) before/after each workload.
- **Disk:** DB dir size, number of files, bytes written/read by the process (`/proc/pid/io`, `pidstat -d`, `iostat`;
  Windows PerfMon IO counters; macOS `fs_usage`/`iotop`), write amplification = bytes written / bytes of user data.
  FD / handle counts over time (leak check for 9.9 fix). WAL and `LOG` sizes (we set `max_log_file_size=1MiB`).
- **Latency:** DB open time, `compactFiles` startup time, p50/p99/p999 per-op latencies in W8, write-stall counts
  (grep `LOG`/glog for "Stalling writes"/"Stopping writes").
- **Binary:** size, load time, page-fault count at start (`/usr/bin/time -v`), idle RSS right after start.

### 11.3 Pass/fail thresholds (from section 2)
CPU median <= +5%, steady-state RSS <= +10%, peak RSS <= +10%, DB open/startup <= +20%, DB dir size <= +10%, no
upward RSS/FD/handle slope beyond baseline. Anything outside -> root cause (option default change? block cache size?
filter/index caching? new background threads? `max_open_files`?). Fix by pinning old defaults, never by guessing.
Report improvements too (with confidence intervals) - this is the empirical answer to "do we see any performance win?".

### 11.4 Output
Per platform: table of medians/p95 per workload (OLD, NEW, delta, p-value), time-series plots (RSS, CPU, FDs, DB size),
flame-graph diffs for W3/W4/W8, and the RocksDB property dumps.

---

## 12. Phase 9 - Sanitizers, soak, and compatibility sweeps

### 12.1 Sanitizers (Linux)
Options exist: `OSQUERY_ENABLE_ADDRESS_SANITIZER`, `OSQUERY_ENABLE_THREAD_SANITIZER`,
`OSQUERY_ENABLE_LEAK_SANITIZER`, `OSQUERY_ENABLE_VALGRIND_SUPPORT` (ASAN and Valgrind are mutually exclusive;
see `cmake/options.cmake`). Build tests+osqueryd with ASAN, TSAN, LSAN (separately) for OLD and NEW; run the full unit
suite plus W7, 9.1 and 9.2 (shortened). Triage reports; classify as pre-existing (appears on OLD) vs new. Note
RocksDB itself is not compiled with sanitizers' instrumentation unless the toolchain flags propagate - confirm flags
reach `thirdparty_rocksdb` (`thirdparty_cxx_settings`).
Also: Valgrind `memcheck` run of `osqueryi` open/close and a short `osqueryd` run.

### 12.2 CPU capability sweep
x86_64 without SSE4.2 and/or PCLMULQDQ (QEMU), old Xeons, AMD; aarch64 without CRC extension (`HAS_ARMV8_CRC` OFF in
the README flags) - verify no `SIGILL`. macOS arm64 vs Rosetta.

### 12.3 OS/filesystem sweep
Linux distros of interest (old glibc container, Alpine/musl N/A?), ext4/xfs/btrfs/overlayfs/tmpfs; macOS oldest
supported (deployment target 10.15 per `cmake/toolchain.cmake`) and newest; Windows 10/11/Server 2016+ (and Win7 floor
as per `_WIN32_WINNT`, if still supported - confirm with maintainers).

### 12.4 Soak
72 h per OS (1 host each; Linux both archs if possible) running W2 + periodic W4 bursts + weekly-style chaos (kill -9
every 30 min, restart service, rotate logs). Track: crashes, `repairDB` events (`<db>.backup` existence), RSS/FD
slopes, DB size, error log lines mentioning `RocksDB:`/`Corruption`/`IO error`. Compare OLD soak on identical hosts in
parallel (A/B on pairs of machines).

### 12.5 Staged rollout (post-merge, not part of this PR)
Recommend shipping in an alpha/pre-release first and watching crash/telemetry reports (corruption-wipe frequency,
startup time) before stable.

---

## 13. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| New default `format_version`/checksum break rollback | Old agent wipes DB (node key, baselines, unshipped events) | Pin options (4.5); matrix (7); negative control R6; PR note |
| Source list/defines mistakes only visible on one platform | Build/link/runtime failure (e.g. missing `HAVE_*` -> slow/wrong CRC) | Script-based diff; per-platform CI; perf test on every OS; `PORTABLE`+runtime dispatch checks |
| New code needing newer libc/OS APIs | Breaks old glibc / macOS 10.15 / Win7 floors | Symbol audit (6.3), build with the same deployment targets, Windows patch review |
| Increased binary size / memory (new features compiled in) | Footprint regression | Size table (5.2), exclude unneeded sources, measure RSS (11) |
| Changed defaults affecting perf (block cache size, readahead, compaction alignment, background threads) | CPU/IO regression | Option-diff review (4.5), pin old values, benchmark |
| MANIFEST/OPTIONS new fields confuse old readers | Rollback corruption | Matrix R-cells; `ldb manifest_dump` inspection; pins (`write_dbid_to_manifest` etc.) |
| Windows file sharing / AV / `AreFilesSame` patch behaviour | Open/recover failures only on Windows | Windows-specific tests (6.3), crash loops with `taskkill /F` |
| Hidden dependency on removed/renamed upstream API in osquery code | Compile errors | Compile on all platforms; grep `rocksdb::` usage list (all in `plugins/database/*`) |
| CVE manifest drift (version not CI-checked) | Scanner noise/misses | Manual verification + the version guard test (6.2 item 7) |
| Reviewer fatigue from large diff | Slow review | Commits: (1) submodule, (2) CMake source/defs, (3) version/manifest/docs, (4) plugin pin + tests; no unrelated changes |

---

## 14. Work breakdown (check off in order)

1. [ ] Phase 0: baseline binaries, logs, fixtures, perf numbers (all platforms).
2. [ ] 4.1 Submodule -> v9.11.2.
3. [ ] 4.2 Source list reconcile (script + manual review) + 4.3 defines/flags.
4. [ ] 4.4 `build_version.cc`, manifest JSON, README, patch review, PCH.
5. [ ] Linux x86_64 local build + existing rocksdb plugin tests.
6. [ ] 4.5 Option-default diff table + pinning + new tests (6.2).
7. [ ] Push; get all 5 platforms green; iterate on per-platform defines.
8. [ ] Phase 2 build-log/warning/size diff report.
9. [ ] Phase 4 compatibility matrix (Linux first) incl. negative control.
10. [ ] Phase 5 corruption + crash scenarios (OLD vs NEW).
11. [ ] Phase 6 evented/differential stress (in-process, then end-to-end).
12. [ ] Phase 7 issue triage.
13. [ ] Phase 8 perf on all platforms; resolve any threshold failures.
14. [ ] Phase 9 sanitizers, CPU/OS sweeps, 72 h soaks.
15. [ ] Compile final report (below) and open the PR following `.github/PULL_REQUEST_TEMPLATE*` if present.

Suggested PR commit layout and title: `libs: Update rocksdb to 10.6.2` (repo convention - see `CHANGELOG.md`
"libs: Update rocksdb to version 6.22.1 (#7330)"). Description must include: motivation, what was pinned and why, rollback
result, perf table, warnings table, list of issues evaluated, risks, and explicit statement about what is **not**
changed (toolchain, C++17).

---

## 15. Final report template (deliver with the PR)

1. Summary and go/no-go recommendation.
2. Build matrix status (5 platforms) + warning/size/time table (5.2).
3. Test results: existing suites, new tests, sanitizers.
4. Compatibility matrix results (7.1) incl. negative control; pins and rationale.
5. Corruption/crash results table OLD vs NEW; list of reproduced fixed bugs and non-reproduced ones.
6. Evented/differential stress results (counts, discrepancies, graphs).
7. Perf: CPU/RSS/disk/latency tables with CIs; flame-graph observations; first-start-after-upgrade cost.
8. GitHub issue triage table.
9. Known risks, follow-ups (e.g. later move to RocksDB >= 10.7 after the toolchain is upgraded; revisiting pins/new
   features such as `wal_compression`, newer `format_version` once rollback support for old releases is no longer needed).
10. Raw evidence index (paths/scripts/logs).

---

## 16. Notes and cautions for the agent

- Never modify files inside the RocksDB submodule worktree; use `patches/` + CMake if a patch is unavoidable.
- Keep the diff minimal and mechanical; no formatting-only churn (`clang-format` via the repo's `format_check` target).
- Do not touch toolchain version, `cxx_std_17`, or CI toolchain settings.
- Do not commit fixtures, evidence, or large binaries.
- Prefer measurable claims. If a test cannot be run on a platform (no ES entitlement, no BPF, no Windows host),
  say so explicitly in the report instead of skipping silently.
- If anything surprising appears (new default option affects on-disk compatibility, missing source file, platform
  define mismatch), stop and report rather than guessing.
- Upstream release notes for cross-referencing: `HISTORY.md` in https://github.com/facebook/rocksdb (sections 6.23-9.11).

