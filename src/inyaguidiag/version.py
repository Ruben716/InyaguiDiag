"""Version unica del proyecto.

Se lee desde el CLI, desde el reporte HTML y desde el .spec de PyInstaller.
No duplicar el numero en ningun otro sitio.
"""

__version__ = "0.1.0"

# Rango de sistemas soportados. Condiciona toda la base de codigo:
# Python 3.8 es la ultima version con soporte oficial de Windows 7.
MIN_WINDOWS = "7"
MAX_WINDOWS = "11"
TARGET_PYTHON = (3, 8)
