#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="${APP_NAME:-jenkis-history}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/bin}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/$APP_NAME}"
GOCACHE_DIR="${GOCACHE_DIR:-/tmp/go-build-cache}"

usage() {
  cat <<EOF
Usage: ./build.sh [command]

Commands:
  build   Build the app binary to $OUT_FILE
  run     Run the app with go run .
  clean   Remove the build output directory
  help    Show this help
EOF
}

build_app() {
  mkdir -p "$OUT_DIR" "$GOCACHE_DIR"
  echo "Building $APP_NAME -> $OUT_FILE"
  (
    cd "$ROOT_DIR"
    env GOCACHE="$GOCACHE_DIR" go build -o "$OUT_FILE" .
  )
  echo "Build completed: $OUT_FILE"
}

run_app() {
  mkdir -p "$GOCACHE_DIR"
  echo "Running $APP_NAME"
  (
    cd "$ROOT_DIR"
    env GOCACHE="$GOCACHE_DIR" go run .
  )
}

clean_app() {
  rm -rf "$OUT_DIR"
  echo "Removed $OUT_DIR"
}

COMMAND="${1:-build}"

case "$COMMAND" in
  build)
    build_app
    ;;
  run)
    run_app
    ;;
  clean)
    clean_app
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "Unknown command: $COMMAND" >&2
    usage
    exit 1
    ;;
esac
