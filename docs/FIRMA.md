# Firma de código

## Por qué hace falta

Windows 11 trae **Smart App Control** activado por defecto en las
instalaciones limpias. Bloquea cualquier ejecutable sin firma ni
reputación. Comprobado en la máquina de desarrollo:

```
InyaguiDiag.exe ha sido bloqueado por la directiva de Device Guard
```

```
Id=3118  Smart App Control Block Details
Id=3077  ...did not meet the Enterprise signing level requirements
```

Se bloquea igual desde el USB: la decisión es por firma, no por ruta.

### Lo que NO funciona

| Intento | Por qué falla |
|---|---|
| Certificado autofirmado | SAC no valida "que esté firmado", valida **reputación en la nube de Microsoft**. Un certificado propio no la tiene. |
| Instalar el certificado en Entidades de Confianza | Cambia la confianza local, no la reputación. SAC sigue bloqueando. |
| Pedirle al cliente que desactive SAC | **Nunca hagas esto.** Una vez apagado no se puede volver a activar sin reinstalar Windows. Es un daño permanente a su equipo. |
| Excluirlo del antivirus | SAC es independiente del antivirus. |

### Dónde no molesta

| Escenario | ¿Corre? |
|---|---|
| Windows 7 / 8 / 10 | ✅ SAC no existe |
| Windows 11 actualizado desde Win10 | ✅ SAC queda apagado |
| Windows 11 instalación limpia | ❌ bloqueado sin firma |
| **Arranque WinPE del USB** | ✅ SAC no se aplica |
| **Ejecutar desde código fuente** | ✅ `python.exe` está firmado por la PSF |

Ese último es el atajo para desarrollar: mientras no haya firma, en tu
propia máquina usa `python -m inyaguidiag` en vez del `.exe`.

---

## Camino elegido: SignPath Foundation

Firma **gratuita** para proyectos de código abierto. Es quien firma
smartmontools — verificable en `docs/AUDITORIA-DEPENDENCIAS.md`, donde su
Authenticode dice *SignPath Foundation*.

### Requisitos y estado

Verificados contra las condiciones publicadas en
[signpath.org/terms.html](https://signpath.org/terms.html).

| Requisito | Estado |
|---|---|
| Licencia aprobada por la OSI, sin doble licencia comercial | ✅ MIT |
| Repositorio público | ✅ github.com/Ruben716/InyaguiDiag |
| Sin componentes propietarios | ✅ todas las dependencias son OSS |
| Sin malware ni programas no deseados | ✅ |
| **Sin herramientas de hacking** | ✅ diagnostica, no busca ni explota vulnerabilidades |
| Funcionalidad documentada en la página de descarga | ✅ `README.md` |
| Compilación automatizada y verificable desde el código | ✅ GitHub Actions |
| Aprobación **manual** de cada versión antes de firmar | ✅ solo corre en etiquetas |
| **Política de firma publicada** | ✅ [`CODE-SIGNING-POLICY.md`](CODE-SIGNING-POLICY.md) |
| Roles declarados: Autor, Revisor, Aprobador | ✅ en esa política |
| Verificación en dos pasos en todas las cuentas con acceso | ⬜ **compruébalo en tu cuenta** |
| Proyecto **ya publicado** en la forma que se va a firmar | ⬜ **falta crear el Release** |
| Proyecto mantenido activamente | ⬜ lo evalúan ellos |

> **Dos requisitos que suelen sorprender:**
>
> 1. **SignPath no firma binarios compilados en tu PC.** Solo firma
>    artefactos del CI, porque lo que su firma garantiza es que el binario
>    salió del código público auditable.
> 2. **El proyecto tiene que estar ya publicado** antes de solicitar. No se
>    puede pedir la firma para algo que todavía no se distribuye: hay que
>    tener un Release en GitHub con los binarios (sin firmar, da igual).

### Pasos

**1. Activar la verificación en dos pasos** en GitHub, si no la tienes:
`Settings → Password and authentication → Two-factor authentication`.
Es un requisito y lo van a comprobar.

**2. Verificar que el CI pasa en verde.** Entrar a la pestaña *Actions* del
repositorio. Si el paso *"Verificar el binario compilado"* falla, hay que
arreglarlo antes de solicitar nada: sin binarios no hay qué firmar.

**3. Publicar la primera versión.**

```bash
git tag v0.1.0 -m "Primera version publica"
git push origin v0.1.0
```

Después, en GitHub: `Releases → Draft a new release`, elegir la etiqueta
`v0.1.0`, describir qué es, y **adjuntar los dos ejecutables** que produjo
el CI (se descargan de los artefactos del flujo). Sin firmar, no importa —
lo que hace falta es que exista una descarga pública.

**4. Solicitar en** https://signpath.org/apply

El formulario pide:

| Campo | Qué poner |
|---|---|
| **Repository URL** | `https://github.com/Ruben716/InyaguiDiag` |
| **License** | `MIT` |
| **Download / Release URL** | La URL del Release del paso 3 |
| **Project description** | Qué hace, quién lo usa y qué tipo de archivo se firma (`.exe`) |

Escríbelo **en inglés**: quien lo revisa no necesariamente lee castellano.
Un texto que sirve:

> InyaguiDiag is a portable diagnostic tool for Windows computers
> (Windows 7 through 11). It runs from a USB drive without installing
> anything on the machine being examined, and can also analyse a disk from
> a computer that no longer boots, by reading its event logs, crash dumps
> and registry hives offline from a WinPE rescue environment.
>
> It is aimed at technicians who repair computers for other people, and at
> users who want to understand a failing machine. Every problem it detects
> is reported together with a plain-language explanation and concrete
> repair steps.
>
> The artifacts to be signed are two console executables, `InyaguiDiag.exe`
> for x64 and x86, built with PyInstaller by GitHub Actions from the public
> source.

**5. Esperar.** Suele tardar de unos días a unas semanas. Pueden hacer
preguntas de seguimiento: respóndelas, no es mala señal.

**6. Al aprobar**, entregan `organization-id`, `project-slug` y
`signing-policy-slug`, más un token de API.

**7. Guardar el token** como secreto del repositorio:
`Settings → Secrets and variables → Actions → New repository secret`,
con el nombre `SIGNPATH_API_TOKEN`.
**Nunca dentro de un archivo del repositorio** — un token en el código es
un token filtrado.

**8. Descomentar el paso de firma** en `.github/workflows/build.yml`, que
ya está escrito y marcado, y pegar los identificadores.

**9. Publicar la siguiente versión** con una etiqueta nueva. Ahora sí sale
firmada.

### Después de la primera firma

La reputación en Microsoft **no es inmediata**. Un certificado OV —el que
usa SignPath— la construye con el tiempo y con el número de descargas. Los
primeros binarios firmados pueden seguir marcándose como poco frecuentes,
aunque ya no los bloquea SAC de la misma forma. Con un certificado EV la
reputación es inmediata, pero esos no son gratuitos.

---

## Alternativa: certificado propio

Si el proyecto dejara de ser abierto, o si hace falta reputación inmediata:

| Tipo | Coste anual | Reputación |
|---|---|---|
| OV (Organization Validation) | ~200-400 USD | Se construye con semanas de uso |
| EV (Extended Validation) | ~300-600 USD | Inmediata; suele venir en token físico |

Ambos exigen verificar la identidad de la empresa: documentación legal,
dirección comprobable y a veces una llamada telefónica. No es un trámite
de cinco minutos.

Con el certificado instalado, `build.ps1` firma solo:

```bash
.\build\build.ps1 -Arch x64 -Sign -CertThumbprint <huella>
```

Requiere `signtool.exe`, que viene con el Windows SDK.
