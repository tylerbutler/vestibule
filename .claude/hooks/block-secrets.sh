#!/bin/bash
FILE_PATH=$(jq -r '.tool_input.file_path' < /dev/stdin)

if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
  exit 0
fi

BASENAME=$(basename "$FILE_PATH")

case "$BASENAME" in
  .env.example|.env.sample|.env.template|.env.dist)
    exit 0
    ;;
esac

case "$FILE_PATH" in
  *.env|*/.env|*.env.local|*.env.*.local|*.env.production|*.env.development)
    echo '{"decision":"block","reason":"Refusing to edit .env file. These typically contain real OAuth client secrets or tokens. Edit by hand, or use .env.example for templates."}'
    exit 0
    ;;
  *private_key*|*.pem|*.p12|*.pfx|*.jks|*id_rsa*|*id_ed25519*)
    echo '{"decision":"block","reason":"Refusing to edit what looks like a private key or certificate file. If this is intentional, edit it outside Claude."}'
    exit 0
    ;;
esac

case "$BASENAME" in
  *secret*|*credential*|*[Tt]oken.json|*[Tt]oken.txt)
    case "$BASENAME" in
      *secret*.gleam|*credential*.gleam|*secret*.md|*credential*.md|*_test.gleam|*test_*.gleam)
        exit 0
        ;;
    esac
    echo '{"decision":"block","reason":"Refusing to edit a file that looks like it holds secrets/credentials/tokens. If this is a source file, rename it; if it really holds secrets, edit it outside Claude."}'
    exit 0
    ;;
esac

exit 0
