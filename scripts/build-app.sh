#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

./scripts/build-icon.sh
swift build -c release --product Schwabber
BIN_DIR="$(swift build -c release --show-bin-path)"
APP_DIR="$PROJECT_DIR/dist/Schwabber.app"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
ICON_HASH="$(shasum -a 256 "$PROJECT_DIR/Assets/Schwabber.icns" | cut -c1-12)"
ICON_NAME="Schwabber-$ICON_HASH.icns"
cp "$PROJECT_DIR/Assets/Schwabber.icns" "$APP_DIR/Contents/Resources/$ICON_NAME"
cp "$BIN_DIR/Schwabber" "$APP_DIR/Contents/MacOS/Schwabber"
chmod 755 "$APP_DIR/Contents/MacOS/Schwabber"

cat > "$APP_DIR/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIconFile</key><string>Schwabber.icns</string>
    <key>CFBundleExecutable</key><string>Schwabber</string>
    <key>CFBundleIdentifier</key><string>local.schwabber.app</string>
    <key>CFBundleName</key><string>Schwabber</string>
    <key>CFBundleDisplayName</key><string>Schwabber</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>CFBundleDocumentTypes</key>
    <array><dict>
        <key>CFBundleTypeName</key><string>Packet Capture</string>
        <key>CFBundleTypeRole</key><string>Viewer</string>
        <key>LSHandlerRank</key><string>Alternate</string>
        <key>CFBundleTypeExtensions</key><array><string>pcap</string><string>pcapng</string><string>cap</string><string>dmp</string></array>
    </dict></array>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

/usr/libexec/PlistBuddy -c "Set :CFBundleIconFile $ICON_NAME" "$APP_DIR/Contents/Info.plist"
plutil -lint "$APP_DIR/Contents/Info.plist"
codesign --force --sign - "$APP_DIR"
codesign --verify --strict --verbose=2 "$APP_DIR"
touch "$APP_DIR"
printf '\nBuilt app: %s\n' "$APP_DIR"
