#!/bin/bash
# otool analysis of parser functions in shared cache dylibs
# benchmark-id: LRK-7

echo "=== otool shared cache analysis ==="

# ImageIO: get all symbols containing parser-related patterns
echo ""
echo "=== ImageIO symbols (parser-related, first 100) ==="
nm -U /System/Library/Frameworks/ImageIO.framework/ImageIO 2>/dev/null | \
    grep -iE "decode|parse|read|scan|jpeg|tiff|png|heif|webp|icc|exif|validate|header|buffer|overflow|bound|check|size|length|alloc" | \
    head -100

echo ""
echo "=== CoreText symbols (parser-related, first 100) ==="
nm -U /System/Library/Frameworks/CoreText.framework/CoreText 2>/dev/null | \
    grep -iE "font|glyph|cmap|sfnt|table|parse|read|decode|validate|bound|check|size|offset" | \
    head -100

echo ""
echo "=== CoreGraphics symbols (PDF/ICC, first 100) ==="
nm -U /System/Library/Frameworks/CoreGraphics.framework/CoreGraphics 2>/dev/null | \
    grep -iE "pdf|icc|color.space|parse|scan|stream|decode|read|validate|bound|check" | \
    head -100

echo ""
echo "=== AudioToolboxCore symbols (codec, first 100) ==="
nm -U /System/Library/PrivateFrameworks/AudioToolboxCore.framework/AudioToolboxCore 2>/dev/null | \
    grep -iE "aac|alac|flac|mp3|decode|codec|parse|frame|packet|sample|channel|buffer|validate" | \
    head -100

echo ""
echo "=== libTIFF symbols (all, first 80) ==="
nm -U /System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libTIFF.dylib 2>/dev/null | head -80
# If nm fails on shared cache, try otool
if [ $? -ne 0 ]; then
    echo "(nm failed, trying otool)"
    otool -tV /System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libTIFF.dylib 2>/dev/null | head -200
fi

echo ""
echo "=== libJP2 symbols (all, first 80) ==="
nm -U /System/Library/Frameworks/ImageIO.framework/Versions/A/Resources/libJP2.dylib 2>/dev/null | head -80

# Disassemble specific functions if found
echo ""
echo "=== Key function disassembly ==="

# Try to get CGImageSourceCreateWithData internals
echo "--- CGImageSourceCreateWithData ---"
otool -tV -p _CGImageSourceCreateWithData /System/Library/Frameworks/ImageIO.framework/ImageIO 2>/dev/null | head -50

echo "--- CGPDFDocumentCreateWithProvider ---"
otool -tV -p _CGPDFDocumentCreateWithProvider /System/Library/Frameworks/CoreGraphics.framework/CoreGraphics 2>/dev/null | head -50

echo "--- CGColorSpaceCreateWithICCData ---"
otool -tV -p _CGColorSpaceCreateWithICCData /System/Library/Frameworks/CoreGraphics.framework/CoreGraphics 2>/dev/null | head -50

echo ""
echo "=== DONE ==="
