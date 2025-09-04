# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path

# Get the directory containing this spec file
spec_dir = Path(SPECPATH)
config_file = spec_dir / 'ward_core' / 'config.yaml'

# Verify config file exists
if not config_file.exists():
    raise FileNotFoundError(f"Config file not found: {config_file}")

print(f"Including config file: {config_file}")

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        (str(config_file), '.'),  # Copy config.yaml to root of bundle
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ward-core',
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
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ward-core',
)
