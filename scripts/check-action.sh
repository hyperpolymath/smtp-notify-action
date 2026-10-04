#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Marketplace metadata gate.
#
# GitHub refuses to publish an action whose `description` parses to 125
# characters or more ("Description must be less than 125 characters"), and it
# reads action.yml from the RELEASE TAG, not from main. The rejection therefore
# arrives at the worst possible moment: after the tag exists, in the release
# UI, on a release that cannot be edited out of the problem. The limit is
# written down nowhere in action.yml's schema or in GitHub's metadata
# documentation, so the only place it can be caught cheaply is here.
#
# Two traps this check exists to close, both observed in the wild:
#
#   * A folded scalar (`description: >-`) does not shorten anything. GitHub
#     measures the PARSED value, and folding joins the lines back into one
#     long string. So this script refuses the block forms outright instead of
#     pretending to measure them: a single-line scalar is a shape whose length
#     can be counted offline without a YAML parser, and that is the whole
#     point of the gate.
#   * `grep '^description:' | wc -c` measures the `>-` marker (2 characters)
#     and false-passes on a 430-character description. That is how this
#     repository's own action.yml got to 430 and stayed there.
#
# Run with --selftest to prove the comparison can fail before trusting it.
set -euo pipefail
cd "$(dirname "$0")/.."

# 125 fails, 124 passes: "less than 125".
limit=125

fail() {
  echo "action.yml: $*" >&2
  exit 1
}

# Count the characters of a single-line description value. ASCII-only today;
# `wc -m` counts characters rather than bytes, so a future accented word is
# not silently counted as two.
count() {
  printf '%s' "$1" | wc -m | tr -d ' '
}

# The value of the root-level `description:` key, quoted or bare.
description_value() {
  local line
  line="$(grep -m1 '^description:' action.yml)" || fail "no root-level description: key"
  line="${line#description:}"
  line="${line#"${line%%[![:space:]]*}"}" # ltrim
  line="${line%"${line##*[![:space:]]}"}" # rtrim
  case "$line" in
    '>'|'>-'|'>+'|'|'|'|-'|'|+'|'')
      fail "the description is a block scalar ('${line:-empty}'). GitHub measures the PARSED value, so folding does not shorten it, and it cannot be counted here. Write it as one single-line scalar."
      ;;
  esac
  case "$line" in
    \"*\") line="${line#\"}"; line="${line%\"}" ;;
    \'*\') line="${line#\'}"; line="${line%\'}" ;;
  esac
  printf '%s' "$line"
}

value="$(description_value)"
length="$(count "$value")"

if [ "${1:-}" = "--selftest" ]; then
  # A gate that cannot fail is not a gate: prove the boundary is where it is
  # claimed to be, on both sides of it.
  over="$(printf 'x%.0s' $(seq 1 "$limit"))"
  under="$(printf 'x%.0s' $(seq 1 $((limit - 1))))"
  [ "$(count "$over")" -eq "$limit" ] || fail "selftest: the ${limit}-character probe is not ${limit} characters"
  if [ "$(count "$over")" -lt "$limit" ]; then
    fail "selftest: a ${limit}-character description was accepted; the boundary is wrong"
  fi
  [ "$(count "$under")" -lt "$limit" ] || fail "selftest: a $((limit - 1))-character description was refused"
  echo "selftest ok: ${limit} characters is refused, $((limit - 1)) is accepted"
  exit 0
fi

if [ -z "$value" ]; then
  fail "the description is empty"
fi

if [ "$length" -ge "$limit" ]; then
  cat >&2 <<EOF
action.yml: the description is ${length} characters; GitHub Marketplace refuses to
publish at ${limit} or more. It reads this file from the RELEASE TAG, so this must be
fixed before the next tag, not after the publish button says so.

  ${value}

The full text belongs in README.adoc, which has no length limit and renders on
the listing page.
EOF
  exit 1
fi

# Uniqueness of the NAME is also checked by the publish form and cannot be
# checked offline (it is global across the Marketplace); it is the one
# requirement this gate leaves to the publish attempt.
name="$(grep -m1 '^name:' action.yml | sed 's/^name:[[:space:]]*//')"
[ -n "$name" ] || fail "no root-level name: key"

echo "ok: description is ${length} characters (limit ${limit}), name: ${name}"
