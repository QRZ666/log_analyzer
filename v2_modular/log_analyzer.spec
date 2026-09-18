# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

# 项目根目录
PROJECT_ROOT = Path(SPECPATH)  # SPECPATH 是 .spec 文件所在目录

block_cipher = None

# 数据文件：规则、配置、白名单
datas = [
    (str(PROJECT_ROOT / 'rules.json'), '.'),
    (str(PROJECT_ROOT / 'config.json'), '.'),
    (str(PROJECT_ROOT / 'whitelist.json'), '.'),
]

# 隐藏导入：PyQt5 依赖 + 自己的模块
hiddenimports = [
    'PyQt5.QtCore',
    'PyQt5.QtGui',
    'PyQt5.QtWidgets',
    'PyQt5.sip',
    # 日志分析器模块
    'log_analyzer',
    'log_analyzer.models',
    'log_analyzer.rules',
    'log_analyzer.parser',
    'log_analyzer.analyzer',
    'log_analyzer.whitelist',
    'log_analyzer.config',
    'log_analyzer.geoip',
    'log_analyzer.export',
    'log_analyzer.gui',
    'log_analyzer.gui.main_window',
    'log_analyzer.gui.worker',
    'log_analyzer.gui.widgets',
    'log_analyzer.gui.highlight_delegate',
    # geoip2 可选依赖
    'geoip2',
    'geoip2.database',
    'requests',
    # 标准库
    'json',
    'csv',
    're',
    'html',
    'urllib.parse',
    'ast',
    'dataclasses',
    'collections',
    'pathlib',
    'ipaddress',
    'threading',
]

a = Analysis(
    [str(PROJECT_ROOT / 'log_analyzer' / 'main.py')],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='LogAnalyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,           # 不显示控制台窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,               # 如需图标，填写 .ico 路径
)
