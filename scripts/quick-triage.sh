#!/usr/bin/env bash
# DEPRECATED: Use "forensic-cli modules run quick_triage" instead of this wrapper.
set -euo pipefail
exec forensic-cli modules run quick_triage "$@"
