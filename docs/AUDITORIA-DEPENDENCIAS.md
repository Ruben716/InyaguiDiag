# Auditoría de dependencias binarias

**Fecha:** 11 de agosto de 2026
**Auditor:** verificación automatizada previa a la incorporación al proyecto
**Entorno:** Windows 11 Pro 26200, sin privilegios de administrador,
Defender con protección en tiempo real activa (firmas `1.457.108.0`)

## Método

Ningún binario descargado se ejecuta antes de superar la cadena completa.
Todo se descarga primero a una **carpeta de cuarentena** fuera del
proyecto, y solo se incorpora lo que pasa.

```
descarga → hash publicado → firma GPG → Authenticode → Defender → incorporar
                    ↓ falla cualquiera ↓
                         descartar
```

Un principio guía el resto: **verificar una firma contra una clave que
viene del mismo canal no prueba nada**. La huella de la clave se confirma
siempre en una fuente independiente antes de confiar en ella.

---

## 1. Python 3.8.10 (x64 y x86)

| | |
|---|---|
| **Origen** | `api.nuget.org` — paquetes oficiales de la Python Software Foundation |
| **Archivos** | `python.3.8.10.nupkg` (13.56 MB) · `pythonx86.3.8.10.nupkg` (12.67 MB) |
| **Por qué esta vía** | Un `.nupkg` es un ZIP. **No hay instalador, no se ejecuta nada**, no se toca el registro ni el sistema. Reversible borrando la carpeta. |
| **Authenticode** | ✅ `Valid` — *Python Software Foundation*, emisor DigiCert SHA2 Assured ID Code Signing CA |
| **Defender** | ✅ Limpio |
| **Verificación funcional** | ✅ `Python 3.8.10` arranca; importa el proyecto completo; **45/45 tests pasan** |

**Motivo de la versión:** 3.8 es la última con soporte oficial de Windows
7, que es el piso de compatibilidad del proyecto. Está fuera de soporte
desde octubre de 2024; usarla es una decisión consciente, documentada en
`constraints-py38.txt`.

### Hallazgo: conflicto de dependencias real

El anclaje detectó lo que se creó para detectar. `python-evtx` **0.8.x
exige Python ≥ 3.9**; la última publicada para 3.8 es **0.7.4**.

```
requirements.txt      python-evtx>=0.7.4     ← límite inferior, no subir
constraints-py38.txt  python-evtx==0.7.4     ← techo duro del build
```

La API que usa el proyecto (`Evtx(...).records()`, `record.xml()`) es
idéntica en ambas series — verificado por introspección bajo 3.8.

---

## 2. smartmontools 7.5 — ⚠️ NO INCORPORADO

| | |
|---|---|
| **Origen** | `github.com/smartmontools/smartmontools`, release `RELEASE_7_5` |
| **Archivo** | `smartmontools-7.5.win32-setup.exe` (1.44 MB) |
| **MD5 publicado** | `bb1e199ad6a3db3e1c27ae54b835cbd5` |
| **MD5 calculado** | `bb1e199ad6a3db3e1c27ae54b835cbd5` ✅ **coincide** |
| **Firma GPG** | ✅ `Good signature` — clave RSA `0C9577FD2C4CFCB4B9A599640A30812EFF3AEFF5` |
| **Huella confirmada aparte** | ✅ La documentación oficial publica `0C95 77FD 2C4C FCB4 B9A5 9964 0A30 812E FF3A EFF5` — coincide |
| **Authenticode** | ✅ `Valid` — *SignPath Foundation*, emisor GlobalSign GCC R45 CodeSigning CA 2020 |
| **Defender** | ✅ Limpio |

### Nota sobre la clave expirada

GPG reporta la clave como **expirada** (`Smartmontools Signing Key
(through 2025)`). No es un problema: la firma se creó el **30 de abril de
2025**, con la clave vigente. **Expiración no es revocación** — una clave
revocada sería motivo de descarte inmediato; una expirada solo indica que
el proyecto debe rotarla.

### Por qué se detuvo la incorporación

Inspección estática del PE, **antes de ejecutar**:

```
requestedExecutionLevel = requireAdministrator
Tipo: Nullsoft Install System (NSIS)
Conmutadores: soporta /S
```

**El instalador exige elevación.** Se detuvo la incorporación por dos
razones:

1. Ejecutarlo dispararía un UAC. Elevar privilegios e instalar software a
   nivel de sistema es una decisión del usuario, no automatizable.
2. Es desproporcionado: del instalador completo solo necesitamos **un
   archivo**, `smartctl.exe`.

La procedencia del binario es sólida — pasó las cuatro verificaciones. El
bloqueo es de **política, no de confianza**.

### Cómo completarlo

Cualquiera de las dos, ejecutada por el usuario con permisos:

```bash
smartmontools-7.5.win32-setup.exe
```

Luego copiar `smartctl.exe` (y sus DLL) a `tools\x64\` y `tools\x86\`.

O, sin instalar, extraer el NSIS con 7-Zip:

```bash
7z x smartmontools-7.5.win32-setup.exe -osmartmontools-extraido
```

### Impacto de no tenerlo

Ninguno bloqueante. `StorageCollector` degrada a la predicción booleana de
WMI (`MSStorageDriver_FailurePredictStatus`) y emite un aviso de cobertura
incompleta. Se pierden los atributos SMART detallados: sectores
realocados, `percentage_used` de NVMe, bloques de reserva.

**Alternativa a evaluar:** leer SMART por `IOCTL_STORAGE_QUERY_PROPERTY`
con `ctypes`, sin binario externo. Elimina la dependencia y el asunto de
licencia GPL, a costa de perder años de compatibilidad con rarezas de
dispositivos que smartctl ya resuelve.

---

## Estado del punto de restauración

**No se creó.** Requiere privilegios de administrador (`Acceso denegado`).

Se mitigó eliminando aquello contra lo que protegería: Python entró por
extracción de ZIP —sin instalador, sin registro, sin servicios— y
smartmontools no se ejecutó. **No hay nada que revertir**: borrar
`.toolchain/` deja el sistema exactamente como estaba.
