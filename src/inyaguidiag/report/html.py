"""Reporte HTML autocontenido.

RESTRICCION: un solo archivo, sin nada externo.

El reporte se genera en el USB y se abre en el equipo del cliente, que
puede no tener internet -- de hecho, si el diagnostico fue por problemas
de red, seguro no lo tiene. Nada de CDN, nada de fuentes remotas, nada de
imagenes enlazadas. Todo el CSS va incrustado.

Se ve bien impreso, porque a veces el entregable es un papel.
"""

from __future__ import annotations

import html
import os
from datetime import datetime
from typing import Dict, List, Optional

from ..core.models import Finding, ScanReport, Severity
from ..version import __version__

_COLORS = {
    Severity.CRITICAL: ("#b3261e", "#fdecea"),
    Severity.WARNING: ("#a06000", "#fff4e0"),
    Severity.INFO: ("#0b5cad", "#e8f1fb"),
    Severity.OK: ("#1b6b3a", "#e8f5ec"),
}

_CSS = """
*{box-sizing:border-box}
body{margin:0;padding:0;background:#f4f5f7;color:#1c1e21;
 font:15px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:24px 16px 64px}
header{background:#1c2b3a;color:#fff;padding:28px 24px;border-radius:10px}
header h1{margin:0 0 4px;font-size:22px;letter-spacing:.3px}
header .sub{opacity:.75;font-size:13px}
.machine{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
 gap:10px 24px;margin-top:18px;font-size:13px}
.machine div span{opacity:.65;display:block;font-size:11px;text-transform:uppercase;
 letter-spacing:.6px}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}
.tile{flex:1;min-width:130px;background:#fff;border-radius:10px;padding:16px;
 border:1px solid #e3e5e8}
.tile .n{font-size:30px;font-weight:600;line-height:1}
.tile .l{font-size:11px;text-transform:uppercase;letter-spacing:.7px;opacity:.65;
 margin-top:6px}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.8px;opacity:.6;
 margin:32px 0 12px}
.card{background:#fff;border:1px solid #e3e5e8;border-left-width:5px;
 border-radius:8px;padding:18px 20px;margin-bottom:14px}
.card h3{margin:0 0 4px;font-size:16px}
.meta{font-size:11px;opacity:.55;font-family:Consolas,monospace;margin-bottom:12px}
.badge{display:inline-block;padding:2px 9px;border-radius:11px;font-size:11px;
 font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-right:8px}
.what{margin:14px 0;padding:12px 14px;background:#f7f8fa;border-radius:6px;
 font-size:14px}
.what b{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.6px;
 opacity:.55;margin-bottom:4px}
ol.steps{margin:10px 0 0;padding-left:22px}
ol.steps li{margin-bottom:6px}
.auto{display:inline-block;margin-top:10px;font-size:12px;padding:4px 10px;
 background:#e8f1fb;color:#0b5cad;border-radius:5px}
details{margin-top:12px;font-size:12px}
details summary{cursor:pointer;opacity:.6}
.ev{font-family:Consolas,monospace;font-size:11px;background:#f7f8fa;
 padding:8px 10px;border-radius:5px;margin-top:6px;overflow-x:auto}
.gap{background:#fff8e1;border:1px solid #ffe0a3;border-radius:8px;padding:16px 20px}
.gap li{font-size:13px}
footer{margin-top:40px;text-align:center;font-size:11px;opacity:.45}
.none{background:#fff;border-radius:10px;padding:40px;text-align:center;
 border:1px solid #e3e5e8}
.none .big{font-size:36px}
@media print{
 body{background:#fff}
 .card,.tile,.none{break-inside:avoid;border-color:#ccc}
 header{background:#fff;color:#000;border:2px solid #000}
 details{display:none}
}
"""


def render_html(report: ScanReport) -> str:
    """Genera el documento HTML completo del reporte."""
    machine = report.machine
    counts = report.counts()
    findings = report.sorted_findings()

    parts: List[str] = []
    add = parts.append

    add("<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>")
    add("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    add("<title>Diagnostico %s - Inyagui Solutions</title>" % _e(machine.hostname))
    add("<style>%s</style></head><body><div class='wrap'>" % _CSS)

    # -- cabecera ------------------------------------------------------
    add("<header><h1>Reporte de diagnostico</h1>")
    add("<div class='sub'>Inyagui Solutions &middot; InyaguiDiag %s &middot; modo %s</div>"
        % (_e(__version__), _e(report.mode.upper())))
    add("<div class='machine'>")
    for label, value in (
        ("Equipo", machine.hostname),
        ("Sistema", _os_text(machine)),
        ("Hardware", ("%s %s" % (machine.manufacturer or "", machine.model or "")).strip()),
        ("Fecha", report.started_at.strftime("%d/%m/%Y %H:%M")),
    ):
        if value:
            add("<div><span>%s</span>%s</div>" % (_e(label), _e(value)))
    add("</div></header>")

    # -- resumen -------------------------------------------------------
    add("<div class='tiles'>")
    for severity in (Severity.CRITICAL, Severity.WARNING, Severity.INFO):
        color = _COLORS[severity][0]
        add("<div class='tile'><div class='n' style='color:%s'>%d</div>"
            "<div class='l'>%s</div></div>"
            % (color, counts[severity], _e(severity.label)))
    add("<div class='tile'><div class='n'>%.1fs</div><div class='l'>duracion</div></div>"
        % report.duration_seconds)
    add("</div>")

    # -- hallazgos -----------------------------------------------------
    if findings:
        add("<h2>Hallazgos</h2>")
        for finding in findings:
            add(_card(finding))
    else:
        add("<div class='none'><div class='big'>&#10003;</div>"
            "<p>No se detectaron problemas.</p></div>")

    # -- cobertura -----------------------------------------------------
    if report.errors:
        add("<h2>Cobertura incompleta</h2><div class='gap'>")
        add("<p>Estas comprobaciones no se pudieron ejecutar, asi que su area "
            "quedo sin revisar:</p><ul>")
        for error in report.errors:
            add("<li><b>%s</b>: %s</li>" % (_e(error.collector), _e(error.message)))
        add("</ul></div>")

    add("<footer>Generado por InyaguiDiag %s el %s</footer>"
        % (_e(__version__), datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
    add("</div></body></html>")
    return "".join(parts)


def _card(finding: Finding) -> str:
    color, background = _COLORS.get(finding.severity, _COLORS[Severity.INFO])
    out = ["<div class='card' style='border-left-color:%s'>" % color]
    out.append("<span class='badge' style='background:%s;color:%s'>%s</span>"
               % (background, color, _e(finding.severity.label)))
    out.append("<h3 style='display:inline'>%s</h3>" % _e(finding.title))
    out.append("<div class='meta'>%s &middot; %s &middot; confianza: %s</div>"
               % (_e(finding.rule_id), _e(finding.category.value),
                  _e(finding.confidence.name.lower())))
    out.append("<p>%s</p>" % _e(finding.summary))

    remedy = finding.remedy
    if remedy is not None:
        out.append("<div class='what'><b>Que significa</b>%s</div>"
                   % _e(remedy.explanation))
        if remedy.steps:
            out.append("<b style='font-size:12px'>Solucion</b><ol class='steps'>")
            for step in remedy.steps:
                out.append("<li>%s</li>" % _e(step))
            out.append("</ol>")
        if remedy.automatable and _action_available(remedy.action_id):
            extra = " (requiere administrador)" if remedy.requires_admin else ""
            out.append(
                "<div class='auto'>Se puede aplicar con <code>--fix</code>%s</div>"
                % _e(extra)
            )

    if finding.evidence:
        out.append("<details><summary>Ver evidencia tecnica</summary>")
        for item in finding.evidence:
            when = ""
            if item.timestamp is not None:
                when = " &mdash; %s" % item.timestamp.strftime("%d/%m/%Y %H:%M:%S")
            out.append("<div class='ev'>[%s] %s%s</div>"
                       % (_e(item.source), _e(item.detail), when))
        out.append("</details>")

    out.append("</div>")
    return "".join(out)


def _action_available(action_id) -> bool:
    """Si la accion propuesta por la regla existe en esta version.

    `automatable` solo dice que la regla nombro un action_id; esto
    confirma que la accion esta implementada. Prometer un arreglo que no
    existe es peor que no ofrecerlo.
    """
    if not action_id:
        return False
    try:
        from .. import remediation

        return remediation.has_action(action_id)
    except ImportError:
        return False


def _os_text(machine) -> str:
    text = machine.os_name or ""
    if machine.os_build:
        text += " (build %s)" % machine.os_build
    return text.strip()


def _e(value) -> str:
    """Escapa para HTML.

    Todo lo que entra al reporte viene de la maquina analizada: nombres de
    equipo, rutas, mensajes de error del sistema. Nada de eso es confiable
    como HTML, asi que TODO pasa por aca sin excepcion.
    """
    return html.escape(str(value if value is not None else ""), quote=True)


# ----------------------------------------------------------------------


def write_report(report: ScanReport, output_dir: str) -> str:
    """Escribe el HTML y devuelve la ruta.

    Se organiza por equipo y fecha para que el USB acumule el historial de
    todas las maquinas atendidas:

        Reportes/<EQUIPO>/2026-08-11_1530.html
    """
    folder = os.path.join(output_dir, report.machine.slug)
    os.makedirs(folder, exist_ok=True)

    name = report.started_at.strftime("%Y-%m-%d_%H%M") + ".html"
    path = os.path.join(folder, name)

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html(report))
    return path
