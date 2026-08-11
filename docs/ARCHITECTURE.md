# Arquitectura de InyaguiDiag

## 1. Restricciones que definen el diseño

Todo lo que sigue se deriva de cuatro restricciones no negociables:

| # | Restricción | Consecuencia en el diseño |
|---|---|---|
| R1 | Debe funcionar en **Windows 7 hasta 11** | Python 3.8; builds x86 + x64; ningún acceso a WMI puede depender de una sola vía |
| R2 | Debe diagnosticar equipos **que no arrancan** | Dos modos de recolección sobre un mismo motor de reglas |
| R3 | **Vive en un USB** y atiende muchos equipos | Sin instalación, sin dependencias en la máquina destino, reportes por equipo |
| R4 | Cabe en **< 3 GB** con todo y entorno de arranque | WinPE mínimo propio en vez de una suite de terceros |

## 2. Las tres capas

```
                    ┌─────────────────────────────┐
                    │        core/engine.py       │
                    │   único que conoce a todos  │
                    └──────────────┬──────────────┘
           ┌───────────────────────┼───────────────────────┐
           ▼                       ▼                       ▼
   ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
   │  collectors/  │       │    rules/     │       │    report/    │
   │               │       │               │       │               │
   │  RECOLECTAN   │──────▶│  INTERPRETAN  │──────▶│  PRESENTAN    │
   │  no juzgan    │ facts │  emiten       │Finding│               │
   │               │       │  Finding      │       │               │
   └───────────────┘       └───────────────┘       └───────────────┘
```

**La regla de oro: un colector nunca decide si algo está mal.**

Devuelve `47` para sectores realocados; no devuelve `"disco dañado"`. Esa
interpretación vive en `rules/`. Sin esta separación, el modo offline sería
imposible: habría que reescribir el criterio de diagnóstico para cada fuente
de datos.

## 3. Cómo un solo motor sirve a dos escenarios

`ScanContext` abstrae el "dónde":

```python
ctx.evtx_dir      # ONLINE  -> C:\Windows\System32\winevt\Logs
                  # OFFLINE -> D:\Windows\System32\winevt\Logs  (disco montado)
```

Ningún colector escribe `C:\` literalmente. Pregunta al contexto. Cambiar
de una máquina viva a un disco muerto es cambiar el contexto, no el código
de análisis.

| | ONLINE | OFFLINE |
|---|---|---|
| Estado | Windows arrancado | Disco montado desde WinPE |
| Fuentes | WMI, perf counters, servicios, red | Solo archivos: `.evtx`, minidumps, hives |
| Reglas que corren | Todas | Las que no dependen de estado vivo |

## 4. Compatibilidad Win7 → Win11: el puente WMI

Ninguna vía de acceso a WMI cubre el rango completo:

| Vía | Win7 | Win10 | Win11 24H2+ |
|---|---|---|---|
| `wmic.exe` | ✅ | ✅ | ❌ en eliminación |
| PowerShell + `ConvertTo-Json` | ❌ trae PS 2.0 | ✅ | ✅ |
| COM vía pywin32 | ✅ | ✅ | ✅ |

`winapi/wmi_bridge.py` resuelve un backend una sola vez y degrada en cadena:
**COM → PowerShell → wmic**. Los colectores llaman a `query()` y no se
enteran.

> El paquete se llama `winapi` y no `platform` a propósito: `platform` es un
> módulo de la biblioteca estándar y ensombrecerlo es una fuente de fallos
> difíciles de rastrear.

## 5. Tolerancia a fallos

Una herramienta de diagnóstico que se cae ante una máquina rota es inútil,
porque las máquinas rotas son su caso de uso.

- Un colector que lanza excepción → se registra en `report.errors`, el escaneo sigue.
- Una regla que lanza excepción → se registra, las demás siguen.
- Una regla sin sus datos → se salta silenciosamente (`can_evaluate`).

El reporte incluye una sección **COBERTURA INCOMPLETA**. Saber qué *no* se
pudo revisar es tan importante como el hallazgo: sin eso, el usuario cree
que "sin hallazgos" significa "sano".

## 6. Convención de identificadores de regla

`XXX-NNN`, estables y públicos — aparecen en el reporte:

| Prefijo | Área | Prefijo | Área |
|---|---|---|---|
| `STO` | almacenamiento | `BOT` | arranque |
| `MEM` | memoria | `CRA` | pantallazos (BSOD) |
| `NET` | red | `SYS` | sistema |
| `DRV` | controladores | `SEC` | seguridad |
| `PRF` | rendimiento | `PWR` | energía |

Un id retirado **nunca** se reutiliza.

## 7. Confianza y riesgo: dos ejes separados

- **`Confidence`** — qué tan seguro está el motor. Correlacionar eventos
  produce hipótesis, no certezas. "47 sectores realocados" es `CERTAIN`;
  "probablemente el driver de red causó el BSOD" es `LIKELY`.
- **`RiskLevel`** — qué tan peligroso es aplicar el arreglo. `SAFE`
  (limpiar temporales) / `MODERATE` (cambiar DNS) / `INVASIVE` (SFC, DISM).

Se modelan aparte porque son independientes: hay diagnósticos ciertos con
arreglos invasivos y viceversa.

## 8. Agregar una comprobación nueva

Un solo gesto, sin listas centrales que actualizar:

```python
@register_collector
class MiColector(Collector):
    name = "mi-colector"
    provides = "mi.area"
    def collect(self, ctx): ...

@register_rule
class MiRegla(Rule):
    rule_id = "SYS-042"
    requires = ("mi.area",)
    def evaluate(self, facts): ...
```

El registro descubre los módulos por `pkgutil`. **Advertencia de
empaquetado:** PyInstaller no ve imports dinámicos; hay que declararlos en
`hiddenimports` del `.spec`.

## 9. Layout

```
src/inyaguidiag/
  core/         models, context, registry, engine
  collectors/   online/  ·  offline/
  rules/        una familia por área
  knowledge/    catálogo de bugchecks y remedios
  remediation/  acciones ejecutables (con confirmación)
  report/       console · html · json
  winapi/       compatibilidad Windows 7-11
tools/x64  tools/x86    binarios de terceros (smartctl…)
build/                   .spec y scripts de compilación
```

## 9. Empaquetado: el riesgo del descubrimiento dinámico

La sección 8 vende el auto-descubrimiento como una ventaja, y lo es —
hasta que se empaqueta. **PyInstaller analiza imports estáticamente y no
ve nada de lo que hace `pkgutil`.**

El modo de fallo es el peor posible para una herramienta de diagnóstico:

```
.spec incompleto → el .exe compila SIN ERRORES
                 → arranca bien
                 → carga cero reglas
                 → declara "sin problemas" en cualquier equipo
```

Nadie se entera. Por eso:

1. El `.spec` usa `collect_submodules()` sobre los paquetes dinámicos, para
   que agregar una regla no obligue a tocarlo.
2. `build.ps1` ejecuta `--list-checks` **contra el binario compilado**,
   cuenta las reglas y **aborta** si bajan del mínimo. Verificar contra el
   código fuente no sirve: ahí siempre funciona.

Esto no es teórico: la primera compilación produjo un `.exe` que reportaba
éxito y moría al arrancar.

### El entry point no puede ser `__main__.py`

PyInstaller ejecuta el script de entrada sin paquete padre, así que un
`from .cli import main` falla con `attempted relative import with no known
parent package` — otra vez **en ejecución, no al compilar**. Por eso existe
`build/entrypoint.py`, con imports absolutos y fuera del paquete.
