#!/usr/bin/env python3
# inject_smali.py —— apktool 反编译目录注入器
# 用法: python3 inject_smali.py <apktool输出目录>
# 功能:
#   1. AndroidManifest.xml 强制 android:extractNativeLibs="true"（保证我们追加的 .so 被解压）
#   2. 在 Application 类（否则主 Activity）的 <init>()V 里插入
#      System.loadLibrary("dandanhook")
import re
import os
import sys
import glob

root = sys.argv[1]
mf_path = os.path.join(root, 'AndroidManifest.xml')
mf = open(mf_path, encoding='utf-8').read()

# ---- 1. extractNativeLibs ----
if 'extractNativeLibs=' in mf:
    mf = re.sub(r'android:extractNativeLibs="[^"]*"', 'android:extractNativeLibs="true"', mf)
else:
    mf = mf.replace('<application', '<application\n        android:extractNativeLibs="true"', 1)
open(mf_path, 'w', encoding='utf-8').write(mf)
print('[ok] extractNativeLibs=true')

pkg = re.search(r'\bpackage="([^"]+)"', mf).group(1)

# ---- 2. 找注入目标类：Application 优先，主 Activity 兜底 ----
cands = []
m = re.search(r'<application\b[^>]*\bandroid:name="([^"]+)"', mf)
if m:
    cands.append(m.group(1))
for blk in re.finditer(r'<activity\b([^>]*)>(.*?)</activity>', mf, re.S):
    name = re.search(r'android:name="([^"]+)"', blk.group(1))
    if name and 'android.intent.action.MAIN' in blk.group(2) \
             and 'android.intent.category.LAUNCHER' in blk.group(2):
        cands.append(name.group(1))


def class_to_rel(cls):
    if cls.startswith('.'):
        cls = pkg + cls
    return cls.lstrip('.').replace('.', '/') + '.smali'


INSERT = ('    const-string v0, "dandanhook"\n'
          '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')

smali_dirs = sorted(glob.glob(os.path.join(root, 'smali*')))
for cls in cands:
    rel = class_to_rel(cls)
    for d in smali_dirs:
        p = os.path.join(d, rel)
        if not os.path.exists(p):
            continue
        src = open(p, encoding='utf-8').read()
        m2 = re.search(r'(\.method public constructor <init>\(\)V.*?)(\.end method)', src, re.S)
        if not m2:
            print('[warn] %s 没有 <init>()V，跳过' % p)
            continue
        block = m2.group(1)
        lines = block.split('\n')
        out, inserted = [], False
        for ln in lines:
            out.append(ln)
            if inserted:
                continue
            mm = re.match(r'(\s*)\.locals (\d+)', ln)
            mr = re.match(r'(\s*)\.registers (\d+)', ln)
            if mm:
                out[-1] = '%s.locals %d' % (mm.group(1), int(mm.group(2)) + 1)
                out.append(INSERT.rstrip('\n'))
                inserted = True
            elif mr:
                out[-1] = '%s.registers %d' % (mr.group(1), int(mr.group(2)) + 1)
                out.append(INSERT.rstrip('\n'))
                inserted = True
        if not inserted:
            print('[warn] %s 构造函数里没有 .locals/.registers，跳过' % p)
            continue
        src = src.replace(m2.group(1), '\n'.join(out), 1)
        open(p, 'w', encoding='utf-8').write(src)
        print('[ok] 已注入 loadLibrary -> %s' % p)
        sys.exit(0)

sys.exit('!! 找不到可注入的 Application/主 Activity 类')
