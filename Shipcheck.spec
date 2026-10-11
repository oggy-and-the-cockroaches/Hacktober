# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:/Users/Ajay/Desktop/Hacktober/launcher.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/Users/Ajay/Desktop/Hacktober/frontend', 'frontend'), ('C:/Users/Ajay/Desktop/Hacktober/backend/native', 'backend/native')],
    hiddenimports=['uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan', 'uvicorn.lifespan.on', 'uvicorn.lifespan.off', 'fastapi', 'starlette', 'starlette.routing', 'starlette.staticfiles', 'starlette.responses', 'starlette.middleware', 'starlette.middleware.cors', 'pydantic', 'pydantic.deprecated', 'pydantic_core', 'anyio', 'anyio._backends._asyncio', 'sqlite3', 'ctypes', 'backend', 'backend.main', 'backend.database.schema', 'backend.services', 'backend.services.native_inspector', 'backend.services.runtime_monitoring', 'backend.services.scanner', 'backend.services.llm', 'backend.services.workspace', 'backend.services.ai_cache', 'backend.services.remediation', 'backend.services.sandbox', 'backend.api', 'backend.api.projects', 'backend.api.scans', 'backend.api.reports', 'backend.api.runtime', 'backend.api.proxy', 'backend.api.fixes', 'backend.api.sentinel', 'backend.api.sandbox', 'backend.api.remediation', 'backend.scanners', 'backend.scanners.security', 'backend.scanners.privacy', 'backend.scanners.reliability', 'backend.scanners.production', 'backend.scanners.dependency', 'backend.scanners.configuration', 'backend.scanners.runtime', 'backend.scanners.ai_reasoning', 'sentinel_rasp', 'sentinel_rasp.core', 'sentinel_rasp.core.engine', 'sentinel_rasp.core.monitor', 'sentinel_rasp.integrations', 'sentinel_rasp.integrations.fastapi', 'sentinel_rasp.integrations.flask', 'sentinel_rasp.integrations.django'],
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
    name='Shipcheck',
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
    name='Shipcheck',
)
