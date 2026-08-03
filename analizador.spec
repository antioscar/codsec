# -*- mode: python -*-
import sys
import os
from pathlib import Path

block_cipher = None

project_root = Path(os.getcwd())

datas = [
    (str(project_root / 'config' / 'rules'), 'config/rules'),
    (str(project_root / 'config' / 'dependencies'), 'config/dependencies'),
    (str(project_root / 'config' / 'compliance'), 'config/compliance'),
    (str(project_root / 'config' / 'settings.yaml'), 'config'),
    (str(project_root / 'config' / 'sources.yaml'), 'config'),
    (str(project_root / 'config' / 'llm.yaml'), 'config'),
]

hiddenimports = [
    'tree_sitter',
    'tree_sitter_javascript',
    'tree_sitter_python',
    'tree_sitter_php',
    'tree_sitter_java',
    'tree_sitter_go',
    'tree_sitter_c_sharp',
    'tree_sitter_ruby',
    'tree_sitter_typescript',
    'yaml',
]

binaries = []

a = Analysis(
    ['main.py'],
    pathex=[str(project_root)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
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
    name='analizador-seguridad',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='analizador-seguridad',
)
