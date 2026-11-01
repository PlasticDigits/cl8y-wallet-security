#!/bin/bash
# Always stop the inspector build before its application start phase.
bash ./deploy/cipher-export/read-main-state.sh
exit 1
