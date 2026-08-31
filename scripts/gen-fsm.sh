#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Regenerate src/generated/smtp_fsm.zig from the proven Idris2 contract.
# Building the ipkg IS the proof gate: if any property of the protocol table
# stops holding, idris2 exits nonzero and nothing is generated.
set -euo pipefail
cd "$(dirname "$0")/.."

(cd spec && idris2 --build smtp-spec.ipkg)
spec/build/exec/emit-zig > src/generated/smtp_fsm.zig
echo "regenerated src/generated/smtp_fsm.zig"
