#!/bin/bash

set -e

if [ "$(rustup default | grep -cE '^nightly' )" -eq 0 ]; then
    echo "You need to switch to rust nightly!"
    exit 1
fi

# if [ "$(which rustfilt | wc -l )" -eq 0 ]; then
#     echo "You need to have rustfilt on the path"
#     echo "cargo install rustfilt"
#     exit 1
# fi
if [ "$(which llvm-cov | wc -l )" -eq 0 ]; then
    echo "You need to have llvm-cov on the path"
    exit 1
fi
export CARGO_INCREMENTAL=0


export LLVM_PROFILE_FILE
echo "Profile files going into ${LLVM_PROFILE_FILE}"

echo "Running tests"
#shellcheck disable=SC2068

LLVM_PROFILE_FILE="$(pwd)/target/profile/coverage-%p-%m.profraw" RUSTFLAGS="-C instrument-coverage" cargo test

grcov . --binary-path ./target/debug/deps/ \
    -s . \
    -t html \
    --branch \
    --ignore-not-existing \
    --ignore '../*' \
    --ignore "/*" \
    -o target/coverage/html


# PROFDATA="./target/profile/kanidm.profdata"

# llvm-profdata merge  ./target/profile/*.profraw -o "${PROFDATA}"

# llvm-cov report --ignore-filename-regex="\.cargo" \
#     --enable-name-compression \
#     $( \
#       for file in \
#         $( \
#           RUSTFLAGS="-C instrument-coverage" \
#             cargo test --tests --no-run --message-format=json \
#               | jq -r "select(.profile.test == true) | .filenames[]" \
#               | grep -v dSYM - \
#         ); \
#       do \
#         printf "%s %s " -object $file; \
#       done \
#     ) \
#   --instr-profile="${PROFDATA}" --summary-only

# llvm-cov show -Xdemangler=rustfilt target/debug/kanidmd \
#     -instr-profile="${PROFDATA}" \
#     -show-line-counts-or-regions \
#     -show-instantiations \
#     -name-regex="kani.*"