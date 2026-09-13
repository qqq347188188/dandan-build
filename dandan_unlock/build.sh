#!/bin/bash
# 在 macOS 上运行：编译 iOS arm64 独立 dylib（无需 Theos / Substrate）
set -e

clang -dynamiclib -arch arm64 -fobjc-arc \
  -framework Foundation -framework CoreFoundation \
  -miphoneos-version-min=15.0 \
  -o dandan_unlock.dylib dandan_unlock.m

echo "✅ 已生成 dandan_unlock.dylib"
echo "   下一步：用 TrollFools 把它注入蛋蛋不语 App"
