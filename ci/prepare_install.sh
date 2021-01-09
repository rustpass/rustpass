#!/bin/sh
#
#
#

set -eux

prepare_install() {
    echo "Preparing install environment"
    export PATH="$PATH:$HOME/.cargo/bin"
    echo "Install environment prepared."
}

prepare_install

exit 0
