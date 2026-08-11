"""Reporte en consola.

Restriccion de diseno: esto tiene que verse bien en la consola de WinPE y
en el cmd.exe de Windows 7, que son terminales pobres. Por eso:

  * ASCII puro por defecto; los emojis y el box-drawing se rompen alli.
  * Colores ANSI solo si se detecta soporte, nunca a la fuerza.
  * Ancho fijo de 78 columnas, que entra en cualquier consola.
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional, TextIO

from ..core.models import Finding, ScanReport, Severity

WIDTH = 78

_COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.WARNING: "\033[93m",
    Severity.INFO: "\033[96m",
    Severity.OK: "\033[92m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def supports_color(stream: TextIO) -> bool:
    """Detecta si conviene emitir secuencias ANSI.

    WinPE y el cmd.exe clasico de Windows 7 no las interpretan y muestran
    la basura literal, que es peor que no tener color.
    """
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.name != "nt":
        return True
    # Windows 10 build 10586+ soporta ANSI si se habilita el modo virtual.
    if os.environ.get("WT_SESSION") or os.environ.get("TERM"):
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7))
    except Exception:  # noqa: BLE001
        return False


class ConsoleReporter:
    """Imprime un ScanReport de forma legible."""

    def __init__(self, stream: Optional[TextIO] = None, color: Optional[bool] = None) -> None:
        self.stream = stream or sys.stdout
        self.color = supports_color(self.stream) if color is None else color

    # ------------------------------------------------------------------

    def render(self, report: ScanReport, verbose: bool = False) -> None:
        self._header(report)
        self._summary(report)

        findings = report.sorted_findings()
        if findings:
            self._write("")
            self._rule("HALLAZGOS")
            for finding in findings:
                self._finding(finding, verbose=verbose)
        else:
            self._write("")
            self._write("  No se detectaron problemas.")

        self._coverage(report)
        self._footer(report)

    # ------------------------------------------------------------------

    def _header(self, report: ScanReport) -> None:
        machine = report.machine
        self._write("")
        self._write("=" * WIDTH)
        self._write(self._style("  InyaguiDiag  -  Diagnostico de sistema", _BOLD))
        self._write("=" * WIDTH)
        self._write("  Equipo   : %s" % machine.hostname)
        if machine.os_name:
            version = machine.os_name
            if machine.os_build:
                version += "  (build %s)" % machine.os_build
            self._write("  Sistema  : %s" % version)
        if machine.manufacturer or machine.model:
            self._write(
                "  Hardware : %s %s" % (machine.manufacturer or "", machine.model or "")
            )
        self._write("  Modo     : %s" % report.mode.upper())
        self._write("  Fecha    : %s" % report.started_at.strftime("%Y-%m-%d %H:%M:%S"))

    def _summary(self, report: ScanReport) -> None:
        counts = report.counts()
        self._write("")
        self._rule("RESUMEN")
        for severity in (Severity.CRITICAL, Severity.WARNING, Severity.INFO):
            count = counts[severity]
            if count == 0:
                continue
            line = "  %-4s %-14s %d" % (severity.icon, severity.label, count)
            self._write(self._style(line, _COLORS[severity]))
        if report.worst_severity is Severity.OK:
            self._write(self._style("  [OK]  Sin problemas detectados", _COLORS[Severity.OK]))

    def _finding(self, finding: Finding, verbose: bool) -> None:
        color = _COLORS.get(finding.severity, "")
        self._write("")
        self._write(
            self._style(
                "%s %s" % (finding.severity.icon, finding.title.upper()), color + _BOLD
            )
        )
        self._write(self._style("     id: %s  |  area: %s" % (
            finding.rule_id, finding.category.value), _DIM))
        self._write("")
        for line in _wrap(finding.summary, WIDTH - 5):
            self._write("     " + line)

        if finding.evidence and verbose:
            self._write("")
            self._write(self._style("     Evidencia:", _DIM))
            for item in finding.evidence:
                self._write(self._style("       - %s" % item.detail, _DIM))
                self._write(self._style("         fuente: %s" % item.source, _DIM))

        if finding.remedy is not None:
            remedy = finding.remedy
            self._write("")
            for line in _wrap("Que significa: " + remedy.explanation, WIDTH - 5):
                self._write("     " + line)
            if remedy.steps:
                self._write("")
                self._write("     Solucion:")
                for number, step in enumerate(remedy.steps, start=1):
                    wrapped = _wrap(step, WIDTH - 12)
                    self._write("       %d. %s" % (number, wrapped[0]))
                    for extra in wrapped[1:]:
                        self._write("          " + extra)
            if remedy.automatable and _action_available(remedy.action_id):
                tag = "     [ Se puede aplicar con --fix ]"
                if remedy.requires_admin:
                    tag += "  (requiere administrador)"
                self._write("")
                self._write(self._style(tag, _COLORS[Severity.INFO]))

    def _coverage(self, report: ScanReport) -> None:
        """Que NO se pudo revisar. Tan importante como lo que se encontro."""
        if not report.errors:
            return
        self._write("")
        self._rule("COBERTURA INCOMPLETA")
        self._write("  Estas comprobaciones no se pudieron ejecutar:")
        for error in report.errors:
            self._write(self._style("    - %s: %s" % (error.collector, error.message), _DIM))

    def _footer(self, report: ScanReport) -> None:
        self._write("")
        self._write("-" * WIDTH)
        self._write(
            self._style(
                "  %d hallazgos en %.1f s" % (len(report.findings), report.duration_seconds),
                _DIM,
            )
        )
        self._write("")

    # ------------------------------------------------------------------

    def _rule(self, title: str) -> None:
        self._write(self._style("-- %s %s" % (title, "-" * (WIDTH - len(title) - 4)), _BOLD))

    def _style(self, text: str, code: str) -> str:
        if not self.color or not code:
            return text
        return code + text + _RESET

    def _write(self, text: str = "") -> None:
        try:
            self.stream.write(text + "\n")
        except UnicodeEncodeError:
            # Consolas antiguas con code page 437: degradar a ASCII puro.
            self.stream.write(text.encode("ascii", "replace").decode("ascii") + "\n")


def _action_available(action_id) -> bool:
    """Si la accion propuesta por la regla existe de verdad.

    Que un remedio sea `automatable` solo significa que la regla nombro un
    action_id. Prometer "se puede aplicar" y que despues no exista seria
    peor que no ofrecerlo.
    """
    if not action_id:
        return False
    try:
        from .. import remediation

        return remediation.has_action(action_id)
    except ImportError:
        return False


def _wrap(text: str, width: int) -> List[str]:
    """Ajuste de linea simple. Evita textwrap por control del resultado."""
    words = str(text).split()
    if not words:
        return [""]
    lines: List[str] = []
    current = words[0]
    for word in words[1:]:
        if len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines
