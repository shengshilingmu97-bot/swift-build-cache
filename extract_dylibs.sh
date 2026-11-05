#!/bin/bash
# Extract key framework dylibs from shared cache for offline analysis
# benchmark-id: LRK-7

set -e

OUT=/tmp/dylib_extract
mkdir -p "$OUT"

echo "=== Copying framework dylibs ==="

# Direct copy from framework paths (these are symlinks into shared cache on macOS 27)
FRAMEWORKS=(
    "/System/Library/Frameworks/ImageIO.framework/Versions/A/ImageIO"
    "/System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libTIFF.dylib"
    "/System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libJP2.dylib"
    "/System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libJPEG.dylib"
    "/System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libPng.dylib"
    "/System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libGIF.dylib"
    "/System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libRadiance.dylib"
    "/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText"
    "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics"
    "/System/Library/PrivateFrameworks/AudioToolboxCore.framework/Versions/A/AudioToolboxCore"
    "/System/Library/PrivateFrameworks/AppleJPEG.framework/Versions/A/AppleJPEG"
)

for fw in "${FRAMEWORKS[@]}"; do
    name=$(basename "$fw")
    if [ -f "$fw" ]; then
        cp "$fw" "$OUT/$name"
        echo "  OK: $name ($(stat -f%z "$fw") bytes)"
    else
        echo "  SKIP: $name (not found at $fw)"
        # Try dyld_shared_cache_util extract
        DSC="/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
        if [ -f "$DSC" ] && command -v dyld_shared_cache_util >/dev/null 2>&1; then
            echo "  Trying dyld_shared_cache_util..."
            dyld_shared_cache_util -extract "$OUT/dsc_extract" "$DSC" 2>/dev/null || true
        fi
    fi
done

echo ""
echo "=== Extracted files ==="
ls -la "$OUT/" 2>/dev/null
echo ""
echo "=== File types ==="
file "$OUT"/* 2>/dev/null

# Also get symbol lists for the key parsers
echo ""
echo "=== ImageIO symbol grep (parser-related) ==="
nm -U "$OUT/ImageIO" 2>/dev/null | grep -iE "jpeg|tiff|png|heif|webp|decode|parse|read.*header|scan.*line" | head -50

echo ""
echo "=== CoreText symbol grep (font parsing) ==="
nm -U "$OUT/CoreText" 2>/dev/null | grep -iE "font|glyph|cmap|table|sfnt|open.?type|true.?type|read.*table" | head -50

echo ""
echo "=== CoreGraphics symbol grep (PDF parsing) ==="
nm -U "$OUT/CoreGraphics" 2>/dev/null | grep -iE "pdf|icc|color.*space|scan|parse|stream" | head -50

echo ""
echo "=== AudioToolboxCore symbol grep (codec) ==="
nm -U "$OUT/AudioToolboxCore" 2>/dev/null | grep -iE "aac|alac|flac|mp3|decode|codec|parse|frame" | head -50
