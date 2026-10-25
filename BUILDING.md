# Building Bioshock 2 Remastered Combat Crash Fix

by eqagunn - v1.0.0 (2026-10-25)

The repository root contains `README.md`, `readme.htm`, `LICENSE`, and the C source,
header, resource, and build files. The test harness is in `tests/`.
Build outputs and generated test fixtures are ignored by Git. No game binary,
extracted game code, build profile, local toolchain, or runtime DLL is included.

The plugin is written in C and targets Windows x86. Install a MinGW-w64 x86
compiler and resource compiler, then run from this directory in a POSIX shell:

```sh
sh build.sh
```

`CC` and `WINDRES` can override the compiler paths. The result is
`BioShock2HDCombatCrashFix.asi` in the repository root. No runtime DLLs from the compiler toolchain
are required by the plugin. `pattern.h` is the production instruction decoder
and constrained semantic matcher; it contains no executable build profiles.

# Tests

The test harness runs on a Linux host with GCC and Python. From this directory,
install the development dependencies into your Python environment and run:

```sh
python3 -m pip install -r requirements-test.txt
gcc -shared -fPIC -O2 -Wall -Wextra -Werror -Itests/shim -I. \
  -o tests/matcher_host.so tests/matcher_host.c
python3 tests/test_patterns.py /path/to/Bioshock2HD.exe
python3 tests/test_release_binary.py
```

Use an unmodified game executable as the external fixture input. The first test
checks a unique match, extracts its removal routine for generated fixtures, and
produces `helper_fixture.bin` and `native_validation.json`. The second executes
the compiled ASI against generated PE images and mocked Win32 APIs, producing
`binary_validation.json`. No game executables or extracted fixtures are shipped.

The mock Windows header is limited to the native pattern-matcher harness. The
ASI itself is compiled using the real MinGW-w64 Windows headers and import
libraries. Passing these tests is not a Windows or in-game compatibility claim.

The compiled-DLL tests check opt-in logging with an existing log file, no file,
an unwritable file, and a renamed plugin. They also verify the actual compiled
VERSIONINFO author, product names, filenames, and string/numeric versions.

# Release packaging

Player installations need only `BioShock2HDCombatCrashFix.asi` and an x86 ASI
loader. Distribute `readme.htm` and `LICENSE` with the ASI. Do not include an empty
log file: its presence explicitly enables logging.

