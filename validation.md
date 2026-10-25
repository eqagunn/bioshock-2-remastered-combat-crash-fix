# Validation — Bioshock 2 Remastered Combat Crash Fix

by eqagunn - v1.0.0 (2026-10-25)

## Release checks

- Unique validated pattern in one real Bioshock 2 Remastered executable.
- 82 native pattern-matcher cases passed.
- 21 compiled-DLL initialization cases passed in Unicorn.
- 6 replacement-instruction execution cases passed.
- Compiled VERSIONINFO numeric and string versions, author, product names, and filenames verified.
- PE32 DLL, ASLR/NX, InitializeASI export, kernel32.dll imports only.
- No OutputDebugString import or automatic log-file creation.
- No EXE hashes, timestamp checks, fixed patch addresses, or build profiles.

## Binary identity

- Filename: `BioShock2HDCombatCrashFix.asi`
- SHA-256: `9fa01e923ea754b67422854659dcb85df7894764951b8a742fd34f305f7a3fd0`

The release checksum identifies this compiled ASI. It is not a game-build allowlist.

## Pattern coverage

Generated fixtures cover different register allocations, short and near branches,
8-bit and 32-bit field displacements, moved functions, direct and forwarding
calls, no-shrink code recognition, invalid helpers, incomplete patterns, and
duplicate matches. These are synthetic variations, not independently tested
storefront executables.

## Compiled DLL cases

- `normal`: APPLIED: actor-array no-shrink patch verified (memory only).
- `relocated`: APPLIED: actor-array no-shrink patch verified (memory only).
- `registers_fields`: APPLIED: actor-array no-shrink patch verified (memory only).
- `direct_call`: APPLIED: actor-array no-shrink patch verified (memory only).
- `metadata`: APPLIED: actor-array no-shrink patch verified (memory only).
- `cross_page`: APPLIED: actor-array no-shrink patch verified (memory only).
- `already_patched`: ALREADY_PATCHED: matching no-shrink instructions are present; no write needed.
- `no_match`: UNSUPPORTED: no validated actor-compaction pattern found; no bytes were written.
- `partial_patch`: UNSUPPORTED: no validated actor-compaction pattern found; no bytes were written.
- `ambiguous`: REFUSED: multiple validated actor-compaction patterns; no bytes were written.
- `wrong_arch`: REFUSED: executable memory could not be validated as readable x86 PE code.
- `invalid_sections`: REFUSED: executable memory could not be validated as readable x86 PE code.
- `unreadable`: REFUSED: executable memory could not be validated as readable x86 PE code.
- `protect_error`: REFUSED: VirtualProtect failed; no bytes were written.
- `partial_protect_error`: REFUSED: VirtualProtect failed; no bytes were written.
- `cache_error`: FAILED: write/cache verification failed; original instructions restored.
- `restore_error`: APPLIED_WITH_WARNING: patch active, but restoring code-page protection failed.
- `changed_during_init`: REFUSED: matched instructions changed during initialization.
- `log_absent`: APPLIED (logging disabled)
- `log_unwritable`: APPLIED (logging disabled)
- `log_renamed_plugin`: APPLIED: actor-array no-shrink patch verified (memory only).

The logging checks verify that CreateFile uses TRUNCATE_EXISTING, which requires
an existing file. A missing or unwritable log produces no WriteFile calls while
the patch still applies. A renamed ASI still uses the fixed requested log filename
beside the plugin. Existing logs are closed once after initialization, and a
second InitializeASI call makes no additional API calls.

Replacement execution checks confirm that only the intended count field changes
and that registers and the stack are preserved. Failure-path checks exercise
cache rollback, page protection, cross-page writes, unreadable code, and changes
between scanning and writing.

## Limits

Windows APIs are mocked in the Unicorn harness. Windows/Ultimate ASI Loader
integration and in-game behavior of this compiled release have not been executed
here. No claim of compatibility with every EXE version is made. Additional real
executables and in-game testing are needed to establish wider compatibility.
