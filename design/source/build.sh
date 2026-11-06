#!/bin/sh
# Rebuild DESIGN.md from these sources, then validate it.
#
#   design/source/build.sh           writes DESIGN.md at the repo root
#   design/source/build.sh OUT.md    writes OUT.md instead, to check a build without touching DESIGN.md
#
# Needs python3 (built and checked with Python 3.13). Intermediate files go to asm/v7/ and are git-ignored.
set -eu
src=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$src/../.." && pwd)
out=${1:-"$root/DESIGN.md"}
case $out in /*) ;; *) out="$(pwd)/$out" ;; esac
mkdir -p "$(dirname "$out")"
cd "$src/asm"
python3 -I extract.py "$src" v7/extract.json > /dev/null
python3 -I fields.py v7/extract.json v7/qfields.json > /dev/null
python3 -I cites10.py "$src" v7/cites.json > /dev/null
python3 -I assemble10.py "$src" "$src/asm" "$out" design/design-research > v7/assemble_stdout.txt
python3 -I validate10.py "$src" "$src/asm" "$out" "$root/design/design-research" "$src/asm/v7/validate.json" > v7/validate_stdout.txt
echo "built $out"
echo "validation: $src/asm/v7/validate.json (summary in asm/v7/validate_stdout.txt)"
