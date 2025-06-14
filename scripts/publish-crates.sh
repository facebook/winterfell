#!/bin/sh

# Script to publish all Winterfell crates to crates.io.
# Usage: ./publish-crates.sh [args]
#
# E.G:   ./publish-crates.sh
#        ./publish-crates.sh --dry-run

set -e

# Checkout
echo "Checking out main branch..."
git checkout main
git pull origin main

# Publish
echo "Publishing crates..."
crates=(
winter-utils
winter-rand-utils
winter-maybe-async
winter-math
winter-crypto
winter-fri
winter-air
winter-prover
winter-verifier
winterfell
)
for crate in ${crates[@]}; do
    echo "Publishing $crate..."
    cargo publish -p "$crate" $@
done