#!/bin/sh
set -eu
cd "$(dirname "$0")"
compiler=${CC:-i686-w64-mingw32-gcc}
resource_compiler=${WINDRES:-i686-w64-mingw32-windres}
"$resource_compiler" --preprocessor="$compiler" --preprocessor-arg=-E \
  --preprocessor-arg=-xc --preprocessor-arg=-DRC_INVOKED -i version.rc -o version.o
"$compiler" -std=c11 -O2 -Wall -Wextra -Werror \
  -ffreestanding -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -shared -nostdlib -Wl,--entry,_DllMain@12 \
  -Wl,--dynamicbase,--nxcompat,--no-insert-timestamp,--image-base,0x68000000 \
  -o BioShock2HDCombatCrashFix.asi \
  BioShock2HDCombatCrashFix.c BioShock2HDCombatCrashFix.def version.o -lkernel32
