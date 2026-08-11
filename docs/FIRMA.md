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

| Requisito | Estado |
|---|---|
| Licencia aprobada por la OSI | ✅ MIT (`LICENSE`) |
| Repositorio público | ✅ github.com/Ruben716/InyaguiDiag |
| Compilación en un servicio de CI | ✅ `.github/workflows/build.yml` |
| El binario debe salir del CI, no de una máquina local | ✅ |
| Proyecto con utilidad demostrable | ⬜ lo evalúan ellos |

> **El requisito que sorprende:** SignPath **no firma binarios compilados
> en tu PC**. Solo firma artefactos producidos por el CI, porque lo que su
> firma garantiza es que el binario salió del código público que cualquiera
> puede auditar. Por eso el flujo de GitHub Actions no es opcional.

### Pasos

1. **Verificar que el CI compila.** Hacer un push y comprobar que el flujo
   `build` termina en verde y publica el artefacto `inyaguidiag-binaries`.
   Si el paso "Verificar el binario compilado" falla, arreglarlo antes de
   solicitar nada.

2. **Solicitar en** https://signpath.org/apply
   Datos que piden: URL del repositorio, licencia, descripción del
   proyecto, y para qué sirve el binario firmado.

3. **Al aprobar**, entregan `organization-id`, `project-slug` y
   `signing-policy-slug`, más un token de API.

4. **Guardar el token** como secreto del repositorio, con el nombre
   `SIGNPATH_API_TOKEN`:
   `Settings → Secrets and variables → Actions → New repository secret`
   Nunca dentro de un archivo del repositorio.

5. **Descomentar el paso de firma** en `.github/workflows/build.yml` (está
   escrito y marcado como pendiente) y pegar los identificadores.

6. **Publicar una versión** con una etiqueta:
   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```
   El trabajo de firma solo corre en etiquetas: SignPath tiene cuota y no
   tiene sentido gastar una firma por cada commit.

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
