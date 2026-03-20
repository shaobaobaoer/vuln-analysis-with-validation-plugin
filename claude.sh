#!/bin/bash

DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
if [ -n "$ANTHROPIC_BASE_URL" ]; then
  SKILLS=$(find "${DIR}/security-skills" -name "*.md" | sort | while read f; do echo "=== $f ==="; cat "$f"; echo; done)
else
  SKILLS="Current Dir is ${DIR}"
fi
claude --verbose  --output-format stream-json --dangerously-skip-permissions  --append-system-prompt "${SKILLS}" -p << EOF
 /ralph-loop:ralph-loop  $1 --max-iterations  20


EOF

