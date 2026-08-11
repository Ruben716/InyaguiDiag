# InyaguiDiag

**Inyagui Solutions**

Diagnóstico portable de equipos Windows. Corre desde un USB, sin instalar
nada en la máquina que revisa, y sirve tanto para un Windows arrancado como
para un disco que ya no bootea.

**Rango soportado: Windows 7 → Windows 11.**

---

## Qué hace

1. Escanea hardware, registros de eventos, pantallazos azules y red.
2. Cada problema detectado viene con **qué significa** y **cómo se arregla**.
3. Distingue lo que puede arreglar solo de lo que necesita manos.
4. Dice explícitamente qué **no** pudo revisar.

## Estado actual

| Fase | Alcance | Estado |
|---|---|---|
| 1 | Núcleo + almacenamiento + CLI | ✅ |
| 2 | Motor de Event Log + correlación temporal | ✅ |
| 3 | Análisis de BSOD / minidumps | ✅ |
| 4 | Diagnóstico de red por capas | ✅ |
| 5 | Base de conocimiento + reporte HTML/JSON | ✅ |
| 6 | Modo offline (disco que no arranca) | ✅ |
| 7 | Empaquetado + WinPE + Ventoy | ✅ |
| 8 | Acciones de reparación con confirmación | ✅ |

## Uso

```bash
python -m inyaguidiag
```

| Comando | Para qué |
|---|---|
| `InyaguiDiag.exe` | Escaneo completo del equipo actual |
| `InyaguiDiag.exe --quick` | Solo comprobaciones rápidas |
| `InyaguiDiag.exe --verbose` | Muestra la evidencia de cada hallazgo |
| `InyaguiDiag.exe --offline D:\Windows` | Analiza un disco que no arranca |
| `InyaguiDiag.exe --list-checks` | Qué sabe revisar esta versión |
| `InyaguiDiag.exe --open` | Abre el reporte HTML al terminar |
| `InyaguiDiag.exe --no-save` | Solo pantalla, sin escribir archivos |
| `InyaguiDiag.exe --detect` | Busca instalaciones de Windows en los discos |
| `InyaguiDiag.exe --fix` | Ofrece aplicar los arreglos, uno por uno |
| `InyaguiDiag.exe --list-actions` | Qué arreglos sabe aplicar |

Códigos de salida: `0` sin problemas · `1` advertencias · `2` críticos ·
`3` error · `4` se aplicó algo que requiere reiniciar.

### Reparación: cuatro cerrojos

`--fix` no aplica nada solo. Entre la detección y el cambio hay cuatro
barreras deliberadas:

1. **`dry_run=True` es el valor por defecto.** La llamada descuidada
   simula; ejecutar de verdad exige escribirlo, y se ve en el diff.
2. **Confirmación tipada obligatoria.** Solo se obtiene pasando la vista
   previa de *esa* acción: el tipo del argumento fuerza el orden
   "mostrar primero, ejecutar después".
3. **Sin terminal interactiva no se aplica nada.** Si la salida está
   redirigida o corre desde un script, se avisa y se omite: nadie estaría
   ahí para aprobarlo.
4. **Solo `s` o `si` cuentan como sí.** Enter, Ctrl+C o cualquier otra
   cosa es no. Ante la duda, no se toca la máquina ajena.

### Reportes

Cada escaneo deja un HTML (para leer o imprimir) y un JSON (para comparar
escaneos y para integraciones), organizados por equipo y fecha:

```
Reportes/<EQUIPO>/2026-08-11_1530.html
Reportes/<EQUIPO>/2026-08-11_1530.json
```

Guardado en el USB, esto se vuelve el **historial de todas las máquinas
atendidas**. El HTML es autocontenido: se abre sin internet, que suele ser
justo el caso cuando el diagnóstico fue por problemas de red.

### Diagnóstico de red: un solo culpable

Cuando no hay cable conectado, también falla el DHCP, el gateway, el DNS e
internet. Reportar las cinco cosas es cierto e inútil. El colector prueba
la conectividad como una escalera y las reglas señalan **solo el primer
peldaño roto**:

```
adaptador → enlace → dirección → puerta → nombres → salida
   NET-001   NET-002   NET-003    NET-004  NET-005  NET-006
```

## Desarrollo

El código **no** vive en el USB. Se desarrolla en disco interno y el USB es
el destino de despliegue.

```bash
pip install -r requirements-dev.txt
set PYTHONPATH=src
python -m inyaguidiag --list-checks
```

### Los dos entornos

| | Desarrollo | Build |
|---|---|---|
| Python | 3.11+ (el que tengas) | **3.8** obligatorio |
| Dependencias | `requirements.txt` | `+ constraints-py38.txt` |
| Para qué | escribir y probar | generar el `.exe` distribuible |

Python 3.8 es la última versión con soporte oficial de Windows 7. Es una
restricción del proyecto, no una preferencia. En la práctica:

- Nada de `match`, uniones con `|`, ni `dict[str,x]` en anotaciones evaluadas.
- `from __future__ import annotations` en todos los módulos.
- El desarrollo puede hacerse con un Python más nuevo, pero **el build
  final se compila con 3.8** o no arrancará en Windows 7.

```bash
py -3.8 -m pip install -r requirements.txt -c constraints-py38.txt
```

### Rendimiento del acceso a WMI

Sin `pywin32` el puente cae al backend de PowerShell, que lanza un proceso
por consulta (~0.9 s cada una). Con `pywin32` instalado usa COM y baja a
milisegundos. Instalarlo es opcional para desarrollar, obligatorio para el
build distribuible.

### Herramientas externas

`tools/x64/` y `tools/x86/` esperan binarios de terceros que **no** están en
el repositorio:

| Binario | Para qué | Licencia |
|---|---|---|
| `smartctl.exe` | Atributos SMART reales | GPL v2 |

Sin `smartctl` el diagnóstico de discos degrada a la predicción booleana de
WMI, que es mucho menos precisa.

⚠️ **Pendiente:** el instalador de smartmontools exige privilegios de
administrador, por lo que no se incorporó automáticamente. Pasó todas las
verificaciones de seguridad — ver [`docs/AUDITORIA-DEPENDENCIAS.md`](docs/AUDITORIA-DEPENDENCIAS.md)
para el detalle y los pasos para completarlo.

### Toolchain de Python 3.8

No está versionado. Se regenera extrayendo los paquetes nuget oficiales de
la PSF en `.toolchain/` (sin instalador, sin tocar el sistema):

```bash
.toolchain\py38-x64\tools\python.exe -m pytest tests -q
```

## Compilar y armar el USB

```bash
.\build\build.ps1 -Usb F: -Arch x64
```

El script compila con el toolchain de Python 3.8, corre las pruebas y
**verifica el binario ya compilado** antes de desplegarlo.

> ⚠️ **Por qué esa verificación no es opcional.** El registro de colectores
> y reglas se llena por descubrimiento dinámico (`pkgutil`), que PyInstaller
> no ve. Si `hiddenimports` queda incompleto, el `.exe` **se compila sin un
> solo error** y declara sano cualquier equipo que analice. `build.ps1`
> cuenta las reglas del binario y aborta si faltan.

Para el entorno de rescate arrancable (requiere Windows ADK y administrador):

```bash
.\build\winpe.ps1 -Arch amd64 -Iso
```

Guía completa en [`docs/USB.md`](docs/USB.md).

> ⚠️ **Windows 11 con Smart App Control bloquea el ejecutable sin firmar.**
> Comprobado, no es teoría. Afecta solo al modo online sobre instalaciones
> limpias de Win11; Windows 7/8/10 y el arranque WinPE del USB funcionan
> igual. Mientras tanto, en la máquina de desarrollo usa
> `python -m inyaguidiag`: `python.exe` sí está firmado.
> Procedimiento completo en [`docs/FIRMA.md`](docs/FIRMA.md).

## Flujo en un equipo que no arranca

1. Arrancar el equipo desde el USB (menú de Ventoy → ISO de InyaguiPE)
2. `InyaguiDiag.exe --detect` — busca las instalaciones de Windows solas.
   Dentro de WinPE las letras cambian y el disco averiado casi nunca es `C:`
3. `InyaguiDiag.exe --offline D:\Windows`

En ese modo se leen los `.evtx`, los minidumps y los hives del registro
directamente del disco, sin que su Windows tenga que arrancar. Cuatro
reglas son específicas de este escenario:

| | |
|---|---|
| `BOT-001` | Archivos esenciales ausentes o de 0 bytes |
| `BOT-002` | BCD ausente o vacío |
| `BOT-003` | Actualización de Windows a medio aplicar |
| `BOT-004` | Disco lleno impidiendo el arranque |

## Licencia

MIT — ver [`LICENSE`](LICENSE).

`smartctl` (GPL v2) **no** se incluye en este repositorio y se invoca como
proceso separado, así que su copyleft no alcanza a este código. Los
detalles y las obligaciones al distribuir un USB que sí lo incluya están en
[`TERCEROS.md`](TERCEROS.md).

## Documentación

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — decisiones de diseño y por qué
- [`docs/USB.md`](docs/USB.md) — armar el pendrive y usarlo en campo
- [`docs/FIRMA.md`](docs/FIRMA.md) — firma de código y Smart App Control
- [`docs/AUDITORIA-DEPENDENCIAS.md`](docs/AUDITORIA-DEPENDENCIAS.md) — verificación de los binarios de terceros
- [`TERCEROS.md`](TERCEROS.md) — licencias del software ajeno
