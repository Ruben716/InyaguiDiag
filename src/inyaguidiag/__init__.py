"""InyaguiDiag: diagnostico portable de equipos Windows (7 a 11).

Escanea hardware, registros de eventos, pantallazos azules y red, tanto en
un equipo arrancado como en un disco que no bootea (montado desde WinPE),
y entrega hallazgos con su solucion.

Arquitectura en tres capas -- ver docs/ARCHITECTURE.md:

    collectors/  recolectan datos crudos. No interpretan.
    rules/       interpretan los datos y emiten hallazgos con remedio.
    report/      presentan los hallazgos.

El motor (core/engine.py) es el unico que conoce a las tres.
"""

from .version import __version__

__all__ = ["__version__"]
