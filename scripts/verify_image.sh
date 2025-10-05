#!/usr/bin/env bash
# verify_image.sh <image> <hashfile>
set -euo pipefail
IMG="$1"
HASHFILE="$2"
sha256sum -c "$HASHFILE"
