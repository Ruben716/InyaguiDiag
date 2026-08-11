"""Acciones de reparacion ejecutables, con confirmacion del usuario.

API para quien integra (el CLI):

    from inyaguidiag import remediation

    accion  = remediation.get_action("clean-temp-files")   # UnknownAction si no existe
    vista   = accion.preview(ctx)                          # no toca nada
    print(vista.as_text())                                 # <- esto ve el usuario

    # 1) Simulacion (es lo que pasa si uno se olvida de todo lo demas):
    resultado = accion.execute(ctx)                        # dry_run=True por defecto

    # 2) Ejecucion real: solo despues de que el usuario diga que si.
    if usuario_acepto:
        ok = remediation.Confirmation.grant(accion, vista, accepted_by="tecnico")
        resultado = accion.execute(ctx, confirmation=ok, dry_run=False)

Sin `confirmation` valida y `dry_run=False`, `execute` lanza
`ConfirmationRequired`. El porque esta explicado en base.py.
"""

from __future__ import annotations

from .base import (  # noqa: F401
    Action,
    ActionPreview,
    ActionResult,
    CommandOutput,
    Confirmation,
    ConfirmationRequired,
    RemediationError,
    UnknownAction,
    action_ids,
    all_actions,
    discover,
    get_action,
    has_action,
    human_size,
    is_valid_interface_name,
    is_valid_ipv4,
    is_valid_volume,
    path_is_within,
    register_action,
    risk_label,
    run_command,
)

__all__ = [
    "Action",
    "ActionPreview",
    "ActionResult",
    "CommandOutput",
    "Confirmation",
    "ConfirmationRequired",
    "RemediationError",
    "UnknownAction",
    "action_ids",
    "actions_for_report",
    "all_actions",
    "discover",
    "execute_action",
    "get_action",
    "has_action",
    "human_size",
    "is_valid_interface_name",
    "is_valid_ipv4",
    "is_valid_volume",
    "path_is_within",
    "preview_action",
    "register_action",
    "risk_label",
    "run_command",
]


def preview_action(action_id, ctx):
    """Vista previa de una accion por su id. No modifica nada.

    Raises:
        UnknownAction: si el id no esta registrado.
    """
    return get_action(action_id).preview(ctx)


def execute_action(action_id, ctx, confirmation=None, dry_run=True):
    """Simula (por defecto) o ejecuta la accion identificada por `action_id`.

    Mismos cerrojos que `Action.execute`: `dry_run=True` por defecto y
    `Confirmation` obligatoria para tocar la maquina.

    Raises:
        UnknownAction: si el id no esta registrado.
        ConfirmationRequired: si `dry_run=False` sin confirmacion valida.
    """
    return get_action(action_id).execute(
        ctx, confirmation=confirmation, dry_run=dry_run
    )


def actions_for_report(report):
    """Acciones aplicables a los hallazgos de un `ScanReport`, sin repetir.

    Utilidad para el CLI: recorre los remedios automatizables y devuelve
    una lista de pares (finding, action) en el orden en que el reporte
    muestra los hallazgos (peor primero).
    """
    pairs = []
    seen = set()
    for finding in report.sorted_findings():
        remedy = finding.remedy
        if remedy is None or not remedy.automatable:
            continue
        if remedy.action_id in seen or not has_action(remedy.action_id):
            continue
        seen.add(remedy.action_id)
        pairs.append((finding, get_action(remedy.action_id)))
    return pairs
