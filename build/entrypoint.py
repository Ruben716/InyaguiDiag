"""Punto de entrada para el ejecutable congelado.

POR QUE ESTE ARCHIVO EXISTE
---------------------------
No se puede usar `src/inyaguidiag/__main__.py` como script de PyInstaller.
PyInstaller lo ejecuta como script suelto, sin paquete padre, asi que
cualquier import relativo (`from .cli import main`) falla con:

    ImportError: attempted relative import with no known parent package

Lo grave es COMO falla: PyInstaller compila sin un solo error y el fallo
solo aparece al ejecutar el binario. Un build "exitoso" puede producir una
herramienta muerta.

Aca todos los imports son absolutos y el modulo no pertenece al paquete,
que es justo lo que necesita el empaquetado.
"""

import sys

from inyaguidiag.cli import main

if __name__ == "__main__":
    sys.exit(main())
