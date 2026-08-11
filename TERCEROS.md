# Software de terceros

InyaguiDiag se distribuye bajo licencia MIT (ver `LICENSE`). Este archivo
documenta el software ajeno del que depende y bajo qué términos.

## smartctl (smartmontools) — GPL v2

**No está incluido en este repositorio.** `tools/x64/` y `tools/x86/` están
excluidos por `.gitignore` y hay que poblarlos aparte (ver
`docs/AUDITORIA-DEPENDENCIAS.md`).

Esa exclusión es deliberada, no un descuido. `smartctl` es **GPL v2**, y
distribuir el binario obliga a acompañarlo del código fuente o de una
oferta escrita de entregarlo. Al no incluirlo, este repositorio MIT queda
libre de esa obligación.

InyaguiDiag lo **invoca como proceso separado** (`subprocess`), nunca lo
enlaza ni incorpora su código. Eso no crea una obra derivada, así que la
GPL no se propaga al resto del proyecto.

> **Si alguna vez armas un USB o un instalador que incluya `smartctl.exe`,
> esa distribución sí queda sujeta a la GPL v2**: tienes que acompañarla
> del código fuente de smartmontools o de una oferta escrita válida por
> tres años. Lo más simple es incluir el enlace al código y una copia de
> la licencia junto al binario.

- Proyecto: https://www.smartmontools.org/
- Código: https://github.com/smartmontools/smartmontools
- Licencia: GNU General Public License v2

## Dependencias de Python

| Paquete | Licencia | Para qué |
|---|---|---|
| `pywin32` | PSF | Acceso a WMI por COM y al registro de eventos |
| `psutil` | BSD 3-Clause | Métricas del sistema en vivo |
| `python-evtx` | Apache 2.0 | Lectura de `.evtx` en modo offline |
| `python-registry` | Apache 2.0 | Lectura de hives del registro en modo offline |
| `PyInstaller` | GPL v2 con excepción | Empaquetado |

Sobre **PyInstaller**: su licencia incluye una excepción explícita que
permite distribuir los ejecutables generados bajo los términos que uno
quiera, incluidos los propietarios. Empaquetar con PyInstaller **no**
obliga a liberar el programa empaquetado.

## Herramientas usadas solo durante el desarrollo

No se distribuyen con el producto:

| Herramienta | Licencia | Uso |
|---|---|---|
| 7-Zip | LGPL / dominio público | Extraer el instalador NSIS de smartmontools |
| Windows ADK | EULA de Microsoft | Construir la imagen WinPE |
