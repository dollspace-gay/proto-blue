#!/usr/bin/env bash
# Run a pedantic+nursery clippy sweep with the workspace's categorical
# allow-list applied. Matches the policy documented in the workspace
# Cargo.toml `[workspace.lints.clippy]` table.
#
# Why this script exists: CLI `-W clippy::pedantic` activates the whole
# pedantic group at the command-line lint level, which currently ties
# with the workspace `[lints]` table at priority 0 and beats individual
# allows in the config. Until that's resolved by Cargo (or until we
# flip pedantic on at the workspace level once the count is zero), the
# project-wide allows are passed explicitly here.
#
# Usage:
#   ./scripts/clippy-pedantic.sh                  # full workspace
#   ./scripts/clippy-pedantic.sh -p proto-blue-repo  # one crate
#
# Exits non-zero on hard errors only; pedantic warnings are NOT treated
# as failures here. CI's clippy gate stays at the default lint level
# via .github/workflows/ci.yml.
set -euo pipefail

cd "$(dirname "$0")/.."

exec cargo clippy --workspace --all-targets --all-features "$@" -- \
    -W clippy::pedantic \
    -W clippy::nursery \
    -A clippy::missing_errors_doc \
    -A clippy::missing_panics_doc \
    -A clippy::module_name_repetitions \
    -A clippy::too_long_first_doc_paragraph
