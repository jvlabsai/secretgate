#!/usr/bin/env bash
# Stages the throwaway repo the demo records against.
#
# Kept out of the tape itself because VHS's parser has no escaping for nested
# quotes, and because the credentials are built from fragments here for the same
# reason the test fixtures are: no file in this repository should contain a
# contiguous run of characters shaped like a live key.
set -euo pipefail

DIR="${1:-/tmp/secretgate-demo}"
rm -rf "$DIR"
mkdir -p "$DIR"

AWSK=$(printf '%s' AKIA 4KTNQ7VZL2WXMP3D)
GHT=$(printf '%s' ghp _ 9fK2mQ7xLp4RtY8vN3wZ6bH1jC5sD0aG4eU2)

{
  printf 'AWS_ACCESS_KEY_ID=%s\n' "$AWSK"
  printf 'DATABASE_URL=postgres://svc:h4Kd9wQz2Lp8Nx7@db.internal:5432/orders\n'
  printf 'GITHUB_TOKEN=%s\n' "$GHT"
} > "$DIR/.env"

# Start from a clean vault so placeholder suffixes are reproducible run to run.
secretgate vault --clear >/dev/null 2>&1 || true
