#!/usr/bin/env bash
#
#
#

set -euxo pipefail

: "${1?$0 <parameter>}"

_tool=$1

cargo_check_fmt() {
    cargo fmt --all -- check
}

cargo_clippy() {
    cargo clippy --all
}

_cmd="-1"

case $_tool in
    check-fmt*)
        _cmd=cargo_check_fmt
        ;;
    clippy*)
        _cmd=cargo_clippy
        ;;
    *)
        echo "Unknown command $_cmd - Exit"
        exit 1
        ;;
esac

echo "Running $_cmd"

$_cmd

exit 0