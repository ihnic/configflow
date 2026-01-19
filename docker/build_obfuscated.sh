#!/bin/bash
set -e

echo "=================================================="
echo "ConfigFlow 混淆构建脚本"
echo "=================================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 清理旧的构建文件
echo -e "${YELLOW}[1/6] 清理旧的构建文件...${NC}"
rm -rf dist/ build/ backend_obfuscated/ *.spec

# 安装依赖
echo -e "${YELLOW}[2/6] 安装构建依赖...${NC}"
pip install -q pyarmor pyinstaller

# 使用 PyArmor 混淆代码
echo -e "${YELLOW}[3/6] 使用 PyArmor 混淆代码...${NC}"
pyarmor gen --enable-rft --enable-bcc --enable-jit --output backend_obfuscated backend/

# 检查混淆结果
if [ ! -d "backend_obfuscated" ]; then
    echo -e "${RED}错误: 代码混淆失败${NC}"
    exit 1
fi

echo -e "${GREEN}✓ 代码混淆完成${NC}"
echo "混淆后的文件："
find backend_obfuscated -name "*.py" | head -5

# 创建混淆版本的 spec 文件
echo -e "${YELLOW}[4/6] 生成 PyInstaller spec 文件...${NC}"
cat > config_flow_obfuscated.spec << 'EOF'
# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

datas = []

# 添加版本文件
if os.path.exists('backend/VERSION'):
    datas.append(('backend/VERSION', 'backend'))

if os.path.exists('backend/config_template.json'):
    datas.append(('backend/config_template.json', 'backend'))

# 添加前端构建产物
if os.path.exists('frontend/dist'):
    datas.append(('frontend/dist', 'static'))

# 隐藏导入
hiddenimports = [
    'flask',
    'flask_cors',
    'yaml',
    'requests',
    'urllib3',
    'jwt',
    'webdavclient3',
    'cryptography',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.ciphers',
    'cryptography.hazmat.primitives.ciphers.aead',
    'cryptography.hazmat.primitives.asymmetric',
    'cryptography.hazmat.backends',
]

# 收集混淆后的子模块
hiddenimports += collect_submodules('backend_obfuscated')

a = Analysis(
    ['main.py'],
    pathex=['backend_obfuscated'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# 过滤掉原始的 backend 模块，只保留混淆后的
a.pure = [(name, src, typ) for name, src, typ in a.pure
          if not name.startswith('backend.') or name.startswith('backend_obfuscated.')]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='config_flow',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=True,
    upx=True,
    upx_exclude=[],
    name='config_flow',
)
EOF

# 修改 main.py 使用混淆后的模块
echo -e "${YELLOW}[5/6] 创建启动文件...${NC}"
cat > main_obfuscated.py << 'EOF'
#!/usr/bin/env python3
"""ConfigFlow 主程序入口（混淆版本）"""
import sys
import os

# 添加混淆后的模块路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend_obfuscated'))

# 导入混淆后的应用
from backend_obfuscated.app import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
EOF

# 使用 PyInstaller 打包
echo -e "${YELLOW}[6/6] 使用 PyInstaller 打包二进制文件...${NC}"
pyinstaller --clean --noconfirm config_flow_obfuscated.spec

# 检查构建结果
if [ -f "dist/config_flow/config_flow" ]; then
    echo -e "${GREEN}✓ 构建成功！${NC}"
    echo ""
    echo "构建产物："
    ls -lh dist/config_flow/config_flow
    echo ""
    echo "目录结构："
    ls -la dist/config_flow/ | head -20
    echo ""

    # 检查是否有 .py 源文件泄露
    echo -e "${YELLOW}检查是否有源码泄露...${NC}"
    PY_FILES=$(find dist/config_flow/ -name "*.py" -type f 2>/dev/null | grep -v "__pycache__" | wc -l)
    if [ "$PY_FILES" -eq 0 ]; then
        echo -e "${GREEN}✓ 没有发现 .py 源文件${NC}"
    else
        echo -e "${RED}⚠ 发现 $PY_FILES 个 .py 文件:${NC}"
        find dist/config_flow/ -name "*.py" -type f | grep -v "__pycache__"
    fi

    echo ""
    echo -e "${GREEN}=================================================="
    echo "构建完成！"
    echo "二进制文件位于: dist/config_flow/"
    echo "=================================================${NC}"
else
    echo -e "${RED}错误: 构建失败${NC}"
    exit 1
fi
