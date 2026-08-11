"""Interfaz de linea de comandos de InyaguiDiag.

Uso tipico desde el USB:

    InyaguiDiag.exe                      escaneo completo del equipo actual
    InyaguiDiag.exe --quick              solo comprobaciones rapidas
    InyaguiDiag.exe --offline D:\\Windows analizar un disco que no arranca
    InyaguiDiag.exe --list-checks        que sabe revisar esta version

Codigos de salida (pensados para poder encadenar desde un .bat):
    0  sin problemas
    1  hay advertencias
    2  hay problemas criticos
    3  error de ejecucion
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import List, Optional

from .core.context import ScanContext, is_winpe
from .core.engine import DiagnosticEngine
from .core.models import Severity
from .core.registry import all_collectors, all_rules
from . import remediation
from .report.console import ConsoleReporter
from .report.html import write_report
from .report.json_out import write_json
from .version import __version__

EXIT_OK = 0
EXIT_WARNING = 1
EXIT_CRITICAL = 2
EXIT_ERROR = 3
EXIT_REBOOT = 4      # se aplico algo que exige reiniciar


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="InyaguiDiag",
        description="Diagnostico portable de equipos Windows (7 a 11).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="InyaguiDiag " + __version__)

    mode = parser.add_argument_group("modo de escaneo")
    mode.add_argument(
        "--offline",
        metavar="RUTA_WINDOWS",
        nargs="?",
        const="auto",
        help=(
            "Analizar un disco que no arranca. Sin argumento busca la "
            "instalacion sola; o indicar la carpeta, p.ej. "
            "--offline D:\\Windows"
        ),
    )
    mode.add_argument(
        "--quick", action="store_true", help="Omitir las comprobaciones lentas."
    )
    mode.add_argument(
        "--deep", action="store_true", help="Habilitar analisis costosos."
    )
    mode.add_argument(
        "--only",
        metavar="AREA",
        action="append",
        help=(
            "Limitar a un area (repetible): almacenamiento, red, arranque, "
            "pantallazos, sistema, memoria, controladores, seguridad."
        ),
    )

    out = parser.add_argument_group("salida")
    out.add_argument(
        "-o", "--output", metavar="CARPETA",
        help="Carpeta donde guardar el reporte. Por defecto, junto al ejecutable.",
    )
    out.add_argument("-v", "--verbose", action="store_true", help="Mostrar evidencia.")
    out.add_argument("--no-color", action="store_true", help="Salida sin color.")
    out.add_argument("--debug", action="store_true", help="Log de depuracion.")
    out.add_argument(
        "--no-save", action="store_true",
        help="No guardar el reporte en disco; solo mostrarlo en pantalla.",
    )
    out.add_argument(
        "--open", action="store_true",
        help="Abrir el reporte HTML al terminar.",
    )

    fix = parser.add_argument_group("reparacion")
    fix.add_argument(
        "--fix", action="store_true",
        help=(
            "Al terminar, ofrecer aplicar los arreglos automatizables. "
            "Cada uno se muestra y se confirma por separado; nada se aplica solo."
        ),
    )

    info = parser.add_argument_group("informacion")
    info.add_argument(
        "--list-checks", action="store_true",
        help="Listar colectores y reglas disponibles y salir.",
    )
    info.add_argument(
        "--list-actions", action="store_true",
        help="Listar las acciones de reparacion disponibles y salir.",
    )
    info.add_argument(
        "--detect", action="store_true",
        help=(
            "Buscar instalaciones de Windows en los discos y salir. Pensado "
            "para el entorno de rescate, donde las letras de unidad cambian."
        ),
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.list_checks:
        return _list_checks()

    if args.list_actions:
        return _list_actions()

    if args.detect:
        return _detect()

    try:
        ctx = _build_context(args)
    except ValueError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    reporter = ConsoleReporter(color=False if args.no_color else None)

    engine = DiagnosticEngine()
    report = engine.scan(ctx, on_progress=_progress if not args.debug else None)
    _clear_progress()

    reporter.render(report, verbose=args.verbose)

    for warning in ctx.warnings:
        print("  aviso: %s" % warning, file=sys.stderr)

    reboot_needed = False
    if args.fix:
        reboot_needed = _fix_interactive(report, ctx)

    if not args.no_save:
        _save(report, ctx.output_dir, open_after=args.open)

    if reboot_needed:
        print("")
        print("  IMPORTANTE: hay cambios que requieren reiniciar el equipo.")
        return EXIT_REBOOT

    return _exit_code(report.worst_severity)


# ----------------------------------------------------------------------
# Reparacion
# ----------------------------------------------------------------------


def _fix_interactive(report, ctx) -> bool:
    """Ofrece aplicar los arreglos automatizables, de a uno.

    Devuelve True si algo pidio reinicio.

    Tres cosas que este flujo NO hace, a proposito:

      * No aplica nada sin ver primero la vista previa en pantalla.
      * No acepta una respuesta ambigua: hay que escribir "s".
      * No pregunta si no hay terminal interactiva. Si la salida esta
        redirigida a un archivo o corre desde un script, aplicar cambios
        seria actuar sin que nadie los aprobara: se omite y se avisa.
    """
    pairs = remediation.actions_for_report(report)
    if not pairs:
        print("\n  No hay arreglos automatizables para estos hallazgos.")
        return False

    if not _is_interactive():
        print(
            "\n  Hay %d arreglo(s) disponible(s), pero no hay terminal "
            "interactiva.\n  No se aplica nada sin confirmacion. Ejecuta "
            "--fix desde una consola." % len(pairs),
            file=sys.stderr,
        )
        return False

    print("")
    print("=" * 78)
    print("  ARREGLOS DISPONIBLES (%d)" % len(pairs))
    print("=" * 78)
    print("  Se muestra cada uno y se pregunta por separado.")
    print("  Nada se aplica sin que escribas 's'.")

    reboot_needed = False

    for finding, action in pairs:
        print("")
        print("-" * 78)
        print("  Para: %s" % finding.title)
        print("")

        if not action.can_run(ctx):
            print("  No aplicable: %s" % action.not_applicable_reason(ctx))
            continue

        try:
            preview = action.preview(ctx)
        except Exception as exc:  # noqa: BLE001
            print("  No se pudo preparar el arreglo: %s" % exc, file=sys.stderr)
            continue

        print(preview.as_text())

        if action.requires_admin and not ctx.is_admin:
            print("")
            print("  Requiere administrador y esta sesion no lo es.")
            print("  Vuelve a abrir la herramienta como administrador.")
            continue

        if not _ask("  Aplicar este arreglo?"):
            print("  Omitido.")
            continue

        try:
            grant = remediation.Confirmation.grant(
                action, preview, accepted_by="usuario"
            )
            result = action.execute(ctx, confirmation=grant, dry_run=False)
        except remediation.RemediationError as exc:
            print("  No se aplico: %s" % exc, file=sys.stderr)
            continue
        except Exception as exc:  # noqa: BLE001
            print("  Fallo inesperado: %s" % exc, file=sys.stderr)
            continue

        print("  %s %s" % ("[ok]" if result.success else "[X]", result.message))
        if result.requires_reboot:
            reboot_needed = True

    return reboot_needed


def _is_interactive() -> bool:
    """Si hay una persona al otro lado que pueda confirmar."""
    try:
        return sys.stdin is not None and sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(question: str) -> bool:
    """Confirmacion explicita. Solo 's' o 'si' valen que si.

    Cualquier otra cosa --incluido Enter a secas, Ctrl+C o fin de entrada--
    se interpreta como NO. Ante la duda, no se toca la maquina ajena.
    """
    try:
        answer = input("%s [s/N]: " % question)
    except (EOFError, KeyboardInterrupt):
        print("")
        return False
    return answer.strip().lower() in ("s", "si", "sí")


def _save(report, output_dir: str, open_after: bool = False) -> None:
    """Guarda HTML y JSON. Un fallo al guardar no invalida el escaneo.

    El USB puede estar lleno, protegido contra escritura o haberse
    desconectado. Nada de eso debe hacer que se pierda el diagnostico que
    ya se mostro en pantalla.
    """
    try:
        html_path = write_report(report, output_dir)
        json_path = write_json(report, output_dir)
    except OSError as exc:
        print("  no se pudo guardar el reporte: %s" % exc, file=sys.stderr)
        return

    print("  Reporte guardado:")
    print("    %s" % html_path)
    print("    %s" % json_path)

    if open_after:
        try:
            os.startfile(html_path)  # type: ignore[attr-defined]
        except (AttributeError, OSError) as exc:
            print("  no se pudo abrir el reporte: %s" % exc, file=sys.stderr)


# ----------------------------------------------------------------------


def _build_context(args: argparse.Namespace) -> ScanContext:
    common = {
        "quick": args.quick,
        "deep": args.deep,
        "output_dir": args.output or _default_output_dir(),
        "enabled_categories": args.only,
    }
    if args.offline:
        target = args.offline
        if target == "auto":
            target = _autodetect_target()
        return ScanContext.for_offline_disk(target, **common)

    if is_winpe():
        # Dentro de WinPE la letra del disco averiado casi nunca es C:, asi
        # que sugerir una letra concreta manda al tecnico a adivinar. Se
        # apunta a la deteccion automatica, que es para esto.
        print(
            "Aviso: estamos en el entorno de rescate y no se indico --offline.\n"
            "       Se analizaria el propio WinPE, no el equipo averiado.\n"
            "       Ejecuta primero:  InyaguiDiag.exe --detect\n",
            file=sys.stderr,
        )
    return ScanContext.for_live_system(**common)


def _autodetect_target() -> str:
    """Elige sola la instalacion de Windows a analizar.

    Se usa con `--offline` sin argumento. Si hay varias candidatas se toma
    la de mayor puntaje pero se avisa cual y se listan las otras: elegir en
    silencio el disco equivocado haria que el tecnico diagnostique una
    maquina distinta a la que tiene delante.

    Raises:
        ValueError: si no hay ninguna. El CLI lo convierte en un mensaje
            util en vez de una traza.
    """
    from .core.discovery import find_windows_installations

    found = find_windows_installations()
    if not found:
        raise ValueError(
            "No se encontro ninguna instalacion de Windows en los discos.\n"
            "       Puede estar cifrado con BitLocker, o el controlador de\n"
            "       almacenamiento puede necesitar un driver. Prueba\n"
            "       --detect para ver que unidades se examinaron."
        )

    chosen = found[0]
    print("  Detectado automaticamente: %s" % chosen.windows_root)
    print("    %s" % chosen.describe())
    if len(found) > 1:
        print("  Hay %d instalacion(es) mas; para elegir otra usa --detect y"
              % (len(found) - 1))
        print("  pasa la ruta a --offline.")
    print("")
    return chosen.windows_root


def _default_output_dir() -> str:
    """Reportes junto al ejecutable, o sea dentro del USB."""
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.getcwd()
    return os.path.join(base, "Reportes")


def _list_checks() -> int:
    print("\nColectores disponibles")
    print("-" * 60)
    for collector in all_collectors():
        modes = "/".join(m.value for m in collector.supported_modes)
        admin = " (admin)" if collector.requires_admin else ""
        print("  %-20s -> %-22s [%s]%s" % (
            collector.name, collector.provides, modes, admin))

    print("\nReglas de diagnostico")
    print("-" * 60)
    for rule in all_rules():
        print("  %-10s %-16s %s" % (
            rule.rule_id, rule.category.value, type(rule).__name__))
    print()
    return EXIT_OK


def _list_actions() -> int:
    print("\nAcciones de reparacion disponibles")
    print("-" * 72)
    for action in remediation.all_actions():
        flags = []
        if action.requires_admin:
            flags.append("admin")
        if action.requires_reboot:
            flags.append("reinicio")
        print("  %-24s %-10s %s" % (
            action.action_id,
            remediation.risk_label(action.risk),
            ("(" + ", ".join(flags) + ")") if flags else "",
        ))
        print("      %s" % action.description)
    print("\n  Ninguna se ejecuta sola: usa --fix y confirma una por una.\n")
    return EXIT_OK


def _detect() -> int:
    """Busca instalaciones de Windows en los discos conectados.

    Es lo primero que corre el entorno de rescate: dentro de WinPE las
    letras de unidad no son las de siempre y el disco del equipo averiado
    casi nunca es C:.
    """
    try:
        from .core.discovery import find_windows_installations
    except ImportError:
        print("La deteccion automatica no esta disponible en esta version.",
              file=sys.stderr)
        return EXIT_ERROR

    found = find_windows_installations()
    if not found:
        print("\n  No se encontro ninguna instalacion de Windows en los discos.")
        print("  Si el disco no aparece, puede estar cifrado con BitLocker, o")
        print("  el controlador de almacenamiento puede necesitar un driver.\n")
        return EXIT_WARNING

    print("\nInstalaciones de Windows encontradas")
    print("-" * 72)
    for index, item in enumerate(found, start=1):
        marca = ""
        if item.is_rescue_environment:
            marca = "   <-- este es el entorno de rescate, no lo analices"
        print("  %d. %s%s" % (index, item.windows_root, marca))
        print("     %s" % item.describe())
        print("")

    # find_windows_installations ordena por puntaje: el primero es el
    # candidato mas probable de ser el Windows averiado.
    print("  Para analizar el mas probable:")
    print("      InyaguiDiag.exe --offline %s\n" % found[0].windows_root)
    return EXIT_OK


def _progress(name: str, index: int, total: int) -> None:
    sys.stderr.write("\r  Analizando [%d/%d] %-28s" % (index, total, name))
    sys.stderr.flush()


def _clear_progress() -> None:
    sys.stderr.write("\r" + " " * 60 + "\r")
    sys.stderr.flush()


def _exit_code(worst: Severity) -> int:
    if worst is Severity.CRITICAL:
        return EXIT_CRITICAL
    if worst is Severity.WARNING:
        return EXIT_WARNING
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
