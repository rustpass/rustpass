#!/usr/bin/env bash
#
# Builds the package and run the tests
#

set -euxo pipefail

_mode=${1:-""}
_toolchain=${2:-""}
_opts=${3:-""}
_params=${4:-""}

run_build() {
    local _op=$1
    echo "Running $_op $_mode"
    cargo $_toolchain $_op $_mode $_opts $_params
}

case $_mode in
    release*)
        _mode="--release"
        ;;
    test)
        _mode="--test"
        ;;
    bench)
        _mode="--bench"
        ;;
    *)
        _mode=""
        ;;
esac

run_build clean
run_build check
run_build build
run_build test

echo "Finished."

exit 0