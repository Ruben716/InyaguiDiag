# Armado del USB de diagnóstico

Guía para montar el pendrive que se lleva a las máquinas. Pensada para un
USB de **4 GB**, que es el caso más ajustado.

---

## 1. Los dos escenarios que debe cubrir

| | Windows arranca | Windows NO arranca |
|---|---|---|
| **Cómo se usa** | Se conecta el USB y se hace doble clic | Se arranca el equipo **desde** el USB |
| **Qué corre** | `InyaguiDiag.exe` sobre el Windows del equipo | WinPE del USB, y desde ahí se monta el disco |
| **Modo** | ONLINE | OFFLINE |

El mismo ejecutable sirve para ambos. Es la razón de haber elegido WinPE
en lugar de un Linux live: no hay que mantener dos binarios.

---

## 2. Estructura final

```
F:\
├── InyaguiPE-amd64.iso          ← arrancar aquí si el equipo no bootea
├── InyaguiPE-x86.iso            ← para equipos viejos de 32 bits
└── InyaguiDiag\                 ← accesible como pendrive normal
    ├── Diagnosticar.bat         ← doble clic: lo que usa el técnico
    ├── InyaguiDiag-x64.exe
    ├── InyaguiDiag-x86.exe
    ├── tools\
    │   ├── x64\smartctl.exe
    │   └── x86\smartctl.exe
    └── Reportes\
        └── <EQUIPO>\2026-08-11_1530.html
```

`Reportes\` acumula el historial de **todas las máquinas atendidas**. Es
el activo que se va formando solo.

---

## 3. Presupuesto de espacio

| Componente | Tamaño |
|---|---|
| WinPE amd64 con la herramienta | ~550 MB |
| WinPE x86 con la herramienta | ~480 MB |
| `InyaguiDiag.exe` ×2 arquitecturas | ~20 MB |
| `smartctl.exe` ×2 | ~2.4 MB |
| **Total** | **≈ 1.05 GB** |
| **Libre en un USB de 4 GB** | **≈ 2.65 GB** |

Referencia: Hiren's BootCD PE ocupa poco más de 3 GB él solo, porque
empaqueta más de cien herramientas de terceros. Construir un WinPE mínimo
es lo que hace que quepa.

> **FAT32 y el límite de 4 GB por archivo:** ninguna ISO se acerca, así
> que no es problema. Pero si algún día se agrega un `MEMORY.DMP` de un
> cliente para analizarlo, ojo: esos sí pasan de 4 GB y FAT32 los rechaza.

---

## 4. Procedimiento

### Paso 1 — Compilar la herramienta

```bash
.\build\build.ps1 -Arch x64
```

Y para cubrir equipos de 32 bits:

```bash
.\build\build.ps1 -Arch x86
```

El script **verifica el binario compilado**, no solo el código fuente. Ver
la advertencia en la sección 6: es la comprobación más importante de todo
el proceso.

### Paso 2 — Construir el entorno de rescate

Requiere **Windows ADK + complemento Windows PE** y una consola **como
administrador**.

| | Enlace |
|---|---|
| 1º Windows ADK | https://go.microsoft.com/fwlink/?linkid=2289980 |
| 2º Complemento Windows PE | https://go.microsoft.com/fwlink/?linkid=2289981 |

**El orden importa**: el instalador del complemento espera encontrar el ADK
y falla si no está. Al instalar el ADK basta con marcar **Deployment
Tools**; lo demás no hace falta y ocupa varios GB.

> ⚠️ **Aplica el parche [KB5079391](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-servicing)**
> o posterior. Corrige CVE-2026-25166, una vulnerabilidad en la propia
> herramienta de Microsoft.

```bash
.\build\winpe.ps1 -Arch amd64 -Iso
```

#### Sobre los 32 bits

**El ADK moderno ya no incluye WinPE de 32 bits.** Microsoft lo retiró a
partir del ADK para Windows 11 22H2.

Antes de buscar una solución, comprueba si de verdad hace falta: **WinPE
amd64 arranca en cualquier procesador de 64 bits, sin importar que el
Windows instalado sea de 32**. Y prácticamente todo equipo de 2006 en
adelante lleva procesador de 64 bits, aunque le hayan puesto un Windows 7
de 32.

Solo los procesadores de 32 bits reales —Pentium 4, Atom antiguos— exigen
WinPE x86. Para esos hace falta el complemento del
[ADK para Windows 10 2004](https://go.microsoft.com/fwlink/?linkid=2120253),
que es la última versión que lo incluye.

> Esto **no afecta** al ejecutable x86 de InyaguiDiag: ese sigue haciendo
> falta para el modo online sobre un Windows de 32 bits, y se compila
> igual.

### Paso 3 — Preparar el pendrive con Ventoy

Ventoy se instala una vez en el USB y después las ISOs se copian como
archivos normales; al arrancar aparece un menú para elegir. Nada de volver
a formatear cada vez que cambia una imagen.

1. Descargar Ventoy de `ventoy.net` (el `.zip` de Windows) y **verificar
   el SHA-256 contra el que publican**. Ventoy no firma sus binarios, así
   que el hash es la única prueba de procedencia.
2. Ejecutar `Ventoy2Disk.exe` como administrador
3. **Comprobar dos veces la unidad en *Device*** — si eliges el disco
   equivocado, borras el disco equivocado, y no vuelve a preguntar
4. En *Option → Partition Style*, elegir **MBR**: arranca tanto en equipos
   BIOS como UEFI. GPT solo sirve para UEFI.
5. **Install** — esto borra el pendrive entero
6. Copiar las ISOs a la raíz

Ventoy deja dos particiones: una exFAT grande con letra (los datos) y una
de 32 MB sin letra (el arranque). El ejecutable y sus herramientas van en
la partición de datos, **no dentro de la ISO**.

> Ventaja secundaria: exFAT **no tiene el límite de 4 GB por archivo** de
> FAT32. Si algún día hay que llevarse el `MEMORY.DMP` de un cliente para
> analizarlo, ahora cabe.

### Paso 4 — Desplegar la parte portable

```bash
.\build\build.ps1 -Usb F: -Arch x64
```

---

## 5. Uso en campo

**Si el equipo enciende:** conectar el USB, abrir `InyaguiDiag\` y doble
clic en `Diagnosticar.bat`. Al terminar abre el reporte solo.

**Si el equipo no enciende:**

1. Encender pulsando la tecla de arranque (`F12`, `F11`, `Esc` o `F2`
   según la marca)
2. Elegir el USB, y en el menú de Ventoy la ISO de InyaguiPE
3. Al cargar, la herramienta busca instalaciones de Windows sola
4. Analizar la que corresponda:

```bash
InyaguiDiag.exe --offline D:\Windows
```

> La letra **no** suele ser `C:` dentro de WinPE. Por eso existe la
> detección automática: adivinarla es la primera forma de perder tiempo.

---

## 6. La verificación que no se puede saltar

El registro de colectores y reglas se llena por **descubrimiento dinámico**
(`pkgutil`). PyInstaller analiza los imports de forma estática y no ve
nada de eso.

Si `hiddenimports` en el `.spec` queda incompleto, ocurre lo peor
imaginable en una herramienta de diagnóstico: **el ejecutable se compila
sin reglas, no da ningún error, y declara sano cualquier equipo que
analice.**

Por eso `build.ps1` ejecuta `--list-checks` **contra el binario ya
compilado**, cuenta las reglas y aborta si faltan. Comprobarlo contra el
código fuente no sirve: ahí siempre funciona.

```bash
dist\x64\InyaguiDiag.exe --list-checks
```

Si esa lista sale corta o vacía, el USB no sirve para nada.

---

## 7. Firma de código: no es opcional en Windows 11

> ⚠️ **Comprobado en la máquina de desarrollo, no es teoría.** El
> ejecutable sin firmar **fue bloqueado**:
>
> ```
> InyaguiDiag.exe ha sido bloqueado por la directiva de Device Guard
> ```
> ```
> Id=3118  Smart App Control Block Details
> Id=3077  ...did not meet the Enterprise signing level requirements
> ```
>
> Se bloquea igual desde el USB: la decisión es por firma, no por ruta.

### Qué es Smart App Control

Windows 11 trae **Smart App Control (SAC)**, que bloquea ejecutables sin
firma ni reputación en la nube. Viene **activado por defecto en las
instalaciones limpias** de Windows 11. Se comprueba así:

```bash
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v VerifiedAndReputablePolicyState
```

`1` = activo · `2` = evaluación · `0` = apagado. Una vez apagado no se
puede volver a encender sin reinstalar Windows, así que **nunca hay que
pedirle a un cliente que lo desactive**: es un daño permanente a su equipo
para resolver un problema nuestro.

### Dónde afecta y dónde no

| Escenario | ¿Corre? |
|---|---|
| Windows 7 / 8 / 10 | ✅ SAC no existe |
| Windows 11 actualizado desde Win10 | ✅ SAC queda apagado |
| Windows 11 instalación limpia | ❌ **bloqueado** |
| **Desde WinPE (modo rescate)** | ✅ **SAC no se aplica** |

El modo de rescate del USB **sigue funcionando siempre**. Lo que queda
comprometido es el modo online sobre un Windows 11 reciente — que es
justamente el caso más común en equipos nuevos.

### Cómo resolverlo

1. **Certificado de firma de código.** Un OV cuesta unos 200-400 USD al
   año y la reputación se construye con el tiempo; un EV cuesta más pero
   da reputación inmediata. Es la solución real.
2. **SignPath Foundation** — firma gratuita para proyectos de código
   abierto. Es exactamente lo que usa smartmontools, cuyo instalador
   verificamos en `AUDITORIA-DEPENDENCIAS.md`: su firma Authenticode dice
   *SignPath Foundation*. Si InyaguiDiag se publica como código abierto,
   este camino no cuesta nada.
3. **Mientras tanto:** usar el arranque WinPE del USB, que no está sujeto
   a SAC.

### Antivirus (aparte de SAC)

Medidas ya tomadas contra falsos positivos heurísticos:

- **UPX desactivado** — comprimir el binario es lo que más dispara alertas
- **Recurso de versión incluido** — un ejecutable sin metadatos ni firma
  es exactamente el perfil que buscan los heurísticos
