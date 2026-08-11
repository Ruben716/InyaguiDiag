# -*- mode: python ; coding: utf-8 -*-
"""Especificacion de PyInstaller para InyaguiDiag.

Genera un unico ejecutable portable que corre sin instalar nada en la
maquina analizada.

    py -3.8 -m PyInstaller build/inyaguidiag.spec --distpath dist --workpath build/tmp

EL PROBLEMA DE LOS IMPORTS DINAMICOS
------------------------------------
El registro (core/registry.py) descubre colectores y reglas recorriendo
los paquetes con `pkgutil`. PyInstaller analiza imports de forma estatica
y NO ve nada de eso: sin ayuda, el .exe se construye sin una sola regla y
reporta alegremente "sin problemas" en cualquier maquina.

Es un fallo silencioso y por eso peligroso. Se resuelve declarando los
modulos abajo y verificandolo despues con --list-checks contra el .exe
compilado, no solo contra el codigo fuente.
"""

import os
import sys

sys.path.insert(0, os.path.abspath("src"))

from PyInstaller.utils.hooks import collect_submodules  # noqa: E402

# Los tres paquetes que se cargan dinamicamente. collect_submodules los
# resuelve recursivamente, asi que agregar una regla nueva no obliga a
# tocar este archivo.
hidden = []
for package in (
    "inyaguidiag.collectors",
    "inyaguidiag.rules",
    "inyaguidiag.remediation",
    "inyaguidiag.knowledge",
):
    hidden += collect_submodules(package)

# Dependencias con imports condicionales que el analizador tampoco ve.
hidden += [
    "win32com.client",
    "pythoncom",
    "win32evtlog",
    "winreg",
    # Estos dos se importan dentro de try/except, asi que el analizador
    # los da por opcionales y no los incluye. Si faltan, el modo OFFLINE
    # pierde en SILENCIO la lectura de registros y del registro de
    # Windows: el .exe no falla, simplemente ve menos.
    "Evtx.Evtx",
    "Registry.Registry",
]

block_cipher = None

a = Analysis(
    # entrypoint.py y NO src/inyaguidiag/__main__.py: PyInstaller ejecuta
    # el script sin paquete padre y los imports relativos revientan en
    # tiempo de ejecucion, con la compilacion reportando exito. Ver la
    # nota dentro de entrypoint.py.
    ["entrypoint.py"],
    pathex=["../src"],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    # Recortes: sin esto el .exe pasa de ~9 MB a mas de 30 por arrastrar
    # tkinter y las librerias cientificas. En un USB 2.0 eso se nota al
    # arrancar.
    excludes=[
        "tkinter", "unittest", "pydoc", "doctest", "test",
        "numpy", "pandas", "matplotlib", "PIL", "setuptools", "pip",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="InyaguiDiag",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX dispara falsos positivos de antivirus
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # NO se pide elevacion en el manifiesto: la herramienta debe poder
    # correr como usuario normal y degradar. Pedir admin de entrada haria
    # que en muchos equipos ni se pueda abrir.
    uac_admin=False,
    version="version_info.txt",
)
