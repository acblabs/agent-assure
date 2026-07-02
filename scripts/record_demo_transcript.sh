#!/usr/bin/env bash
set -euo pipefail

# WSL/Git Bash/CI helper for refreshing the checked-in flagship transcript.
rm -rf .tmp/demo-recording
mkdir -p docs/assets
agent-assure demo flagship --out .tmp/demo-recording --clean \
  | tee docs/assets/flagship_demo_transcript.txt
