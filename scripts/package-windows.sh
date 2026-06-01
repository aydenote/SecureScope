#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/frontend"
BACKEND_DIR="$ROOT_DIR/backend"
WWWROOT_DIR="$BACKEND_DIR/wwwroot"
ARTIFACTS_DIR="$ROOT_DIR/artifacts/windows"
PUBLISH_DIR="$ARTIFACTS_DIR/SecureScope"
ZIP_PATH="$ARTIFACTS_DIR/SecureScope-windows-x64.zip"

rm -rf "$WWWROOT_DIR" "$ARTIFACTS_DIR"
mkdir -p "$WWWROOT_DIR" "$PUBLISH_DIR"

npm --prefix "$FRONTEND_DIR" run build
cp -R "$FRONTEND_DIR/dist/." "$WWWROOT_DIR/"

dotnet publish "$BACKEND_DIR/SecureScope.Api.csproj" \
  --configuration Release \
  --runtime win-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:AssemblyName=SecureScope \
  -p:DebugType=None \
  -p:DebugSymbols=false \
  --output "$PUBLISH_DIR"

cp "$ROOT_DIR/scripts/appsettings.LocalPackage.json" "$PUBLISH_DIR/"

(
  cd "$ARTIFACTS_DIR"
  zip -r "$(basename "$ZIP_PATH")" SecureScope
)

printf '\nCreated %s\n' "$ZIP_PATH"
