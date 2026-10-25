# Bioshock 2 Remastered Combat Crash Fix

by eqagunn - v1.0.0 (2026-10-25)

Windows x86 · Ultimate ASI Loader

An ASI plugin targeting invalid-memory reads observed in the game's audio callback during sustained weapon fire. It prevents an avoidable reallocation of the level's actor array during cleanup.

The plugin patches the running process. The game executable on disk stays unchanged, and no configuration file is required.

## Installation

1. Close the game.
2. Install the **Win32/x86** edition of [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader) in the folder containing `Bioshock2HD.exe`, typically `Build\Final`.
3. Copy `BioShock2HDCombatCrashFix.asi` beside the executable, or into its `scripts` or `plugins` folder as allowed by the loader configuration.
4. Launch the game normally. Logging is optional and disabled by default.

Keep the loader's default `DontLoadFromDllMain=1`. The plugin uses the `InitializeASI` entry point for initialization outside the loader lock. The loader is not included. Source files and tests are optional for installation.

## What the fix does

The game maintains an array of pointers to actors: objects belonging to a level. A cleanup routine compacts surviving entries and removes the unused tail. That tail-removal operation can shrink the backing allocation, potentially moving the array and releasing its old storage.

The audio thread also reads this array during an FMOD callback. Crash dumps show invalid reads through an array pointer, and a hardware write breakpoint identifies a gameplay-thread cleanup path that can replace that pointer. These observations support an allocation-lifetime race:

1. The audio thread obtains the array's address.
2. Gameplay cleanup reallocates the array and releases its old storage.
3. The audio thread reads through the old address.

The plugin replaces this tail-removal call with an update to the compacted actor count. It retains the array's backing allocation and capacity. Actor compaction still runs, removed entries stay outside the active count, and removed actors are not kept alive by the fix.

The trade-off is retaining spare pointer-array capacity. Growth allocations still happen. The change addresses this particular cleanup path; other actor-array lifetime changes and unrelated crashes remain outside its scope. The complete failing thread interleaving was not captured instruction by instruction.

## Compatibility and pattern scanning

Detection uses structural pattern scanning without EXE hashes, timestamps, build profiles, or fixed patch addresses. It scans readable executable sections and validates:

- The actor-compaction loop, including its null/deletion checks, scan and retained indices, index-repair call, copy operation, and control-flow targets.
- The relationship between the actor-array field and its element-count field.
- The tail-removal arguments and a compatible pointer-array removal/shrink routine, reached directly or through a checked forwarding wrapper.
- A complete patch range and a compatible function epilogue.

Registers, supported field displacements, relative calls, and the patch location are derived from the matched code. The replacement is generated for that match.

**Exactly one validated match is required.** Missing, ambiguous, partially modified, unreadable, or incompatible patterns are left untouched. Matching no-shrink instructions are recognized without another write.

The plugin supports executable layouts retaining a recognized instruction structure. Compatibility with every released or future EXE version has not been established. Different compiler transformations, engine changes, or packed code may require additional pattern support. Storefront-wide and combined-mod compatibility need independent testing.

Use this plugin with the **32-bit Bioshock 2 Remastered executable**.

## Optional startup log

To enable logging, create an empty file named `Bioshock2HDCombatCrashFix.log` **in the same folder as the ASI** before starting the game. Check that Windows has not added a hidden `.txt` extension.

The plugin writes only when that file already exists and is writable. It replaces the file's contents at startup and never creates the file itself. The log filename stays the same if the ASI is renamed. No log file is included in the download.

With no writable log file, the patch still runs and produces no file or Windows debug-output messages. To disable logging, close the game and delete the log file.

| Status | Meaning |
| --- | --- |
| `APPLIED` | A unique validated pattern was patched and the memory write verified. |
| `ALREADY_PATCHED` | Matching no-shrink instructions are present; no write was needed. |
| `UNSUPPORTED` | No compatible actor-compaction pattern was found. |
| `REFUSED` | Validation failed or was ambiguous, or code-page access could not be obtained. |
| `FAILED` | Write/cache verification failed and the original instructions were restored. |
| `APPLIED_WITH_WARNING` | The patch is active, but restoring a code-page protection failed. |

When checking compatibility, enable logging and verify the startup result. `APPLIED` confirms installation of the patch; it does not guarantee elimination of every possible crash. If an existing log stays empty, check its permissions and the loader's diagnostic log, plugin search folders, and x86 architecture.

## Investigation tools

- **Windows Error Reporting full crash dumps** captured access violations, registers, thread stacks, and relevant process memory.
- **WinDbg** provided live debugging and hardware write breakpoints on the actor-array pointer field. These located the pointer-writing allocator path and its gameplay-thread callers.
- **Python with pefile and Capstone** inspected PE images and disassembled the audio callback, array-removal routine, and actor-compaction code. This identified the tail-removal operation and the instruction change needed to retain the backing allocation.

## Source and validation

The source is written in C and built with **MinGW-w64 GCC**. The ASI is a PE32 DLL with ASLR and NX, imports only `kernel32.dll`, and requires no Visual C++ or MinGW runtime DLL.

Validation covers one real executable with a unique match, 82 native pattern-matcher cases, 21 compiled-DLL initialization cases, and six replacement-instruction execution cases. The DLL cases include opt-in logging with present, missing, and unwritable files. The compiled VERSIONINFO is also checked.

**Unicorn x86 CPU emulation** runs the compiled DLL against generated PE images and mocked Windows APIs, checking bounded memory writes, initialization idempotence, failure rollback, page protection, and actor-count/register behavior. Synthetic fixtures are not independently tested game versions.

Windows/ASI Loader integration and in-game behavior of this compiled release have not been tested here. See [validation.md](validation.md) for the validation boundary and [BUILDING.md](BUILDING.md) for build and test instructions.

## Removal

Close the game, remove `BioShock2HDCombatCrashFix.asi`, and relaunch. An optional log can also be deleted. The plugin does not edit saves, registry entries, or frame-rate settings. Installing, replacing, or unloading it during gameplay is unsupported.

---

Copyright © 2026 eqagunn. Released under the [MIT License](LICENSE).

BioShock, FMOD, and Ultimate ASI Loader belong to their respective owners. This is an independent community modification.
