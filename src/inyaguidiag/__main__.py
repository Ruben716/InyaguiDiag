"""Punto de entrada para `python -m inyaguidiag`.

El import es ABSOLUTO a proposito, no relativo. Un `from .cli import main`
funciona aqui pero se rompe en cuanto este archivo se ejecuta como script
suelto, cosa que hacen tanto PyInstaller como algunos lanzadores.

Para el ejecutable congelado se usa `build/entrypoint.py`; ver la nota
alli sobre por que hace falta un archivo aparte.
"""

import sys

from inyaguidiag.cli import main

if __name__ == "__main__":
    sys.exit(main())
