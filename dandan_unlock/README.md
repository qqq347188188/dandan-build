# 蛋蛋不语 VIP 解锁 dylib

把 QuantumultX 的 `script-response-body` 重写逻辑，搬进 App 进程内用 dylib 直接完成，
不再依赖代理 / MITM。源码与原始 JS 的 `Object.assign` 行为 1:1 一致。

## 文件
- `dandan_unlock.m` —— dylib 源码（纯 ObjC runtime，无 Substrate 依赖）
- `build.sh`         —— macOS 一键编译脚本

## 编译（需在 macOS 上执行）
```bash
cd dandan_unlock
bash build.sh
# 产物: dandan_unlock.dylib
```

> Windows 无法编译 iOS 二进制，必须在 macOS（装了 Xcode / Command Line Tools）上跑。
> 也可以用 Linux + iOS 交叉工具链（cctools + iPhoneOS.sdk）编译，命令相同。

## 注入方式
### 方式 A：TrollFools（最简单，免重签 / 免解密 IPA）
1. 用 TrollStore 安装蛋蛋不语。
2. 打开 TrollFools → 选择蛋蛋不语 → 注入 `dandan_unlock.dylib`。
3. 打开 App 即生效。dylib 通过 `NSLog` 输出 `[dandan_unlock]` 日志，可用 Xcode 控制台 / 系统日志查看。

### 方式 B：Azule 烤进 IPA（永久化，便于分发）
```bash
azule -i dandan.ipa -o dandan_patched.ipa -f dandan_unlock.dylib
# 再用 TrollStore 安装 dandan_patched.ipa
```

## 排查
- **不生效**：先用抓包 / FLEX 确认 App 实际请求是否仍是 `http://38.76.202.248:8000/.../profiles...`，
  以及响应 JSON 的顶层是不是 profile 对象（本 dylib 与 JS 一致只改顶层）。
- **App 走 delegate 模式**（非 completionHandler）：hook 抓不到，需改为 hook App 内解析 profile 的模型方法。
- **已升级 HTTPS**：需额外 hook `URLSession:didReceiveChallenge:completionHandler:` 放行证书。

## 没有 Mac 也能编译

### 方案 A：GitHub Actions 云端编译（推荐，零本地环境）
macOS runner 自带 Xcode + iOS SDK，仓库里已放好 `.github/workflows/build.yml`。

1. 把本仓库（含 `dandan_unlock/` 与 `.github/`）推到 GitHub。
2. 进入仓库 **Actions → Build dandan_unlock.dylib → Run workflow**。
3. 跑完后在 **Artifacts** 里下载 `dandan_unlock.dylib`。

> 需要 GitHub 账号，但全程不需要任何本地编译器。

### 方案 B：本地 macOS
```bash
cd dandan_unlock
bash build.sh          # 需要 macOS + Xcode Command Line Tools
```

### 方案 C：WSL / Linux 交叉编译（无 Mac 无 GitHub）
在 Windows 上启用 WSL Ubuntu，安装 Theos 工具链 + iPhoneOS SDK 后用 clang 编：
```bash
# WSL 内
export THEOS=~/theos
git clone --recursive https://github.com/theos/theos.git $THEOS
# 下载 linux 版工具链到 $THEOS/toolchain/linux/iphone，并 git clone https://github.com/theos/sdks.git $THEOS/sdks
$THEOS/toolchain/linux/iphone/bin/clang -dynamiclib -arch arm64 -fobjc-arc \
  -isysroot $THEOS/sdks/iPhoneOS.sdk -miphoneos-version-min=15.0 \
  -o dandan_unlock.dylib dandan_unlock.m
```

