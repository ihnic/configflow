# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# 收集所有需要的数据文件
import os

datas = []

# 添加版本文件（如果存在）
if os.path.exists('backend/VERSION'):
    datas.append(('backend/VERSION', 'backend'))

if os.path.exists('backend/config_template.json'):
    datas.append(('backend/config_template.json', 'backend'))

# 添加前端构建产物（如果存在）
if os.path.exists('frontend/dist'):
    datas.append(('frontend/dist', 'static'))

# 收集所有隐藏导入
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

# 收集所有子模块
hiddenimports += collect_submodules('backend')

a = Analysis(
    ['main.py'],
    pathex=[],
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

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='config_flow',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
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
    strip=False,
    upx=True,
    upx_exclude=[],
    name='config_flow',
)
