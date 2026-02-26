#!/bin/bash
FILE_PATH=$(jq -r '.tool_input.file_path' < /dev/stdin)

if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
  exit 0
fi

case "$FILE_PATH" in
  *.gleam)
    gleam format "$FILE_PATH" 2>/dev/null
    ;;
esac

exit 0
