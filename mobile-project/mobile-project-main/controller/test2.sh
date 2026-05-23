#!/bin/bash
BODY='{"repository":{"name":"allsafe","clone_url":"https://github.com/t0thkr1s/allsafe"},"ref":"refs/heads/master","after":"abc12345"}'
SIG="sha256=$(echo -n "$BODY" | openssl dgst -sha256 -hmac 'secret_github_webhook' | cut -d' ' -f2)"

curl -X POST http://localhost:8010/webhook/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$BODY"
