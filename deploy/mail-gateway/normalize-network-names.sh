#!/bin/bash
# Docker's outer formatter newline is an empty separator, never a network name.
set -eu -o pipefail
[ "$#" = 0 ]
sed '/^$/d' | sort
