# Binary loading benchmark

The headless harness reads a binary with the production `BinaryFile` loader and runs the same bulk-analysis request used by Binary View, with the real Zydis/Capstone/JVM/GML decoder factory. It never launches the target.

Run from the repository root on Windows with Visual Studio 2022 and the app's installed static decoder dependencies:

```powershell
./tools/run_binary_load_benchmark.ps1 -Binary C:/Windows/System32/notepad.exe -Runs 3
```

The script compiles only the required Core and decoder sources, with `/O2 /MT`, into an isolated temporary directory. It prints the directory containing the executable, compiler log, source hashes, and TSV measurements. Existing app objects are not used. The source dependency list follows the maintained `analysis_service_test` declaration.

Reuse that executable for another binary, or measure retained analysis-cache reuse:

```powershell
./tools/run_binary_load_benchmark.ps1 -ReuseBuild -OutputRoot C:/path/to/artifacts -Binary C:/Windows/System32/ntdll.dll -Runs 3
./tools/run_binary_load_benchmark.ps1 -ReuseBuild -OutputRoot C:/path/to/artifacts -Binary C:/Windows/System32/ntdll.dll -Runs 3 -WarmCache
```

`-SourceRoot C:/path/to/snapshot/src` builds an earlier source snapshot for comparison. `-BuildOnly` prepares the executable without measuring; use it to finish all compilation before timing. Keep target bytes identical across before/after runs. The default timeout is 300 seconds per run, adjustable with `-TimeoutSeconds`.

Interpretation:

- `parsed` and `hashed` measure file read/format parsing and content-hash completion.
- Subsequent times are cumulative milliseconds from the start of the run to result delivery. `complete` includes all requested passes: strings, functions and naming/classification, lazy listing layout, cross-references, algorithms, and triage. Triage also requires the call graph, so its completion is checked separately.
- `process_cpu_ms` uses Windows `GetProcessTimes` for cumulative kernel plus user CPU time across the harness and worker. This helps distinguish work performed from scheduling delays when other applications are active; it does not remove differences in CPU clock speed or memory contention.
- Each ordinary run creates a fresh analysis service with an empty derived-result cache. `-WarmCache` retains that cache after the first run. Windows' filesystem cache is uncontrolled; “cold” output filenames refer only to the derived-result cache.
- Function, string, call-edge, and xref digests catch output changes while counts catch missing results. The listing digest column contains its code-page count. These are smoke-check fingerprints, not a complete semantic equivalence test.
- Visible-page decoding, UI result adoption, project sidecar restoration, runtime/Java shell probes, and symbol work are outside this measurement. Fingerprinting and one-millisecond result polling add small harness overhead. Report medians and retain the individual runs; avoid comparing measurements taken during heavy competing work.

## Measurements from 6 September 2026

The baseline was a clean source snapshot of commit `4b7de8b`. Both versions used freshly compiled optimized production Core/decoder sources and the same harness on Windows, an AMD Ryzen 7 9800X3D (16 logical processors), and approximately 32 GB RAM. The app target was copied before rebuilding so its 18,595,328 bytes stayed identical; its production content hash was `0ef16b27b41723c6`. No target was launched.

**Full-load speed improvement is inconclusive in these measurements.** Other user applications remained active, and both wall and process CPU times drifted substantially. The reversed app comparison changed the apparent winner, so these results do not establish either a general full-load speedup or a reliable regression percentage.

| Target | Bytes | Before full-load wall time | After full-load wall time | Samples |
| --- | ---: | ---: | ---: | --- |
| System32 notepad.exe | 360,448 | 1.249 s median | 1.278 s median | Three each; no clear benefit |
| System32 ntdll.dll | 2,522,072 | 8.250 s median | 10.426 s median | Three each; background load increased during after runs |
| DisasmStudio snapshot | 18,595,328 | 73.076 s, 65.368 s | 70.440 s, 74.364 s | Alternating A/B then B/A; inconclusive |

The app measurements were run in this chronological order:

| Version | Wall time | Process CPU time |
| --- | ---: | ---: |
| Before | 73.076 s | 72.281 s |
| After | 70.440 s | 69.922 s |
| After | 74.364 s | 73.672 s |
| Before | 65.368 s | 64.391 s |

All 16 completed before/after samples had identical per-target content, function, string, call-edge, and xref fingerprints, as well as identical listing-page, algorithm, and triage-artifact counts. Every run completed all seven effective passes with seven cache misses and zero cache hits. The app retained 32,903 functions, 279,829 call edges, and 429,364 xref edges. Its string scan reached the same existing 100,000-result cap in every version; analysis scope was not reduced to improve timing.

The focused optimized regression fixtures isolate the actual algorithm changes more clearly than the noisy full-load runs:

| Focused workload | Before | After |
| --- | ---: | ---: |
| 16,384 functions requiring repeated `nullsub` name suffixes | 8,848.296 ms | 16.567 ms |
| 16,384-function named thunk chain | 1,285.919 ms | 9.141 ms |
| Padding classification over 4 MiB with 8,192 already-covered spans | 123.634 ms | 17.368 ms |

These are timings of individual operations on stress fixtures, **not whole-application load times**. The naming fixtures preserve exact names and reasons. The classifier fixture preserves exact spans, evidence, and coverage, including unaligned ARM/A64/Thumb boundaries.

Local evidence is retained under `build/binary-load-benchmark/`: `before/` and `after/` contain the harness executables and TSVs; `summary.json` records completed run measurements and fingerprints; `fingerprint_checks.json` records equality across each target's samples. The app comparison uses `DisasmStudio.target.exe.paired1.tsv` and `.paired2.tsv`. An interrupted earlier app `.cold.tsv` is excluded from the summary. This build directory is intentionally outside source control.

Session additions and fixes:

- Added a reproducible headless benchmark covering production parsing, hashing, and full initial bulk analysis.
- Added separate cold derived-cache and warm-cache modes, wall/CPU pass timing, result-completion validation, and output fingerprints.
- Added isolated optimized compilation from the current tree or a saved source snapshot, with source hashes and reusable executable/log artifacts.
