#!/bin/sh
# Runs OpenAI Codex CLI headless inside the Blast Radius sandbox.
#   BLAST_MODEL   model id (default gpt-6-astra)
#   BLAST_EFFORT  reasoning effort (default medium)
#   $1            the task prompt
# Codex's own sandbox is disabled because the container is the sandbox: the
# flag below is documented as intended for externally sandboxed environments.
# Model traffic goes to the Blast Radius gateway, which holds the real key.
# Plugin and apps sync are off: on every start Codex otherwise clones
# github.com/openai/plugins (~25 MB, ~8k files) into ~/.codex, which is
# unrelated to the task and drowns the recorded blast radius.
set -e
MODEL="${BLAST_MODEL:-gpt-6-astra}"
EFFORT="${BLAST_EFFORT:-medium}"
mkdir -p "$HOME/.codex"
exec codex exec \
  --dangerously-bypass-approvals-and-sandbox \
  --skip-git-repo-check \
  --ephemeral \
  --json \
  --color never \
  --disable plugins \
  --disable remote_plugin \
  --disable apps \
  -c 'model_providers.blast={name="blast",base_url="http://blast-proxy:8081/v1",wire_api="responses",env_key="OPENAI_API_KEY"}' \
  -c model_provider=blast \
  -c model_reasoning_effort="$EFFORT" \
  -m "$MODEL" \
  "$1" < /dev/null
