# Política de firma de código

*Documento exigido por SignPath Foundation. Describe quién puede modificar
el código, quién aprueba una firma y qué hace el programa con los datos del
equipo que analiza.*

---

## Firma

Las versiones publicadas de InyaguiDiag se firman con un certificado
proporcionado gratuitamente por [SignPath Foundation](https://signpath.org/),
emitido por [SignPath.io](https://signpath.io/).

Este proyecto no dispone de otro certificado. **Un binario de InyaguiDiag
firmado por cualquier otra entidad no proviene de este proyecto.**

## Roles del equipo

InyaguiDiag lo mantiene actualmente una sola persona, que ejerce los tres
roles. Se declara de forma explícita porque SignPath lo exige y porque
conviene ser transparente sobre el tamaño real del proyecto.

| Rol | Quién | Qué puede hacer |
|---|---|---|
| **Autor** | [@Ruben716](https://github.com/Ruben716) | Escribir y modificar código |
| **Revisor** | [@Ruben716](https://github.com/Ruben716) | Aprobar cambios antes de integrarlos |
| **Aprobador** | [@Ruben716](https://github.com/Ruben716) | Autorizar la firma de una versión |

Todas las cuentas con acceso de escritura al repositorio tienen la
**verificación en dos pasos activada**.

Si el equipo crece, este documento se actualiza antes de dar acceso.

## Cómo se construyen los binarios

1. El código vive en https://github.com/Ruben716/InyaguiDiag
2. Cada versión se marca con una etiqueta `vX.Y.Z`
3. **GitHub Actions compila** el ejecutable a partir del código público
   (`.github/workflows/build.yml`). No se firman binarios compilados en la
   máquina de nadie.
4. El flujo verifica que el binario compilado carga todas las reglas de
   diagnóstico antes de publicar el artefacto
5. La firma se solicita **manualmente** para cada versión. No hay firma
   automática por cada cambio.

## Qué hace el programa con los datos

InyaguiDiag es una herramienta de diagnóstico: lee el estado del equipo
para encontrar problemas. Es importante ser preciso sobre qué hace con lo
que lee.

### No envía nada a ninguna parte

**No hay telemetría, ni analíticas, ni envío de reportes.** Todo lo que
recolecta se queda en el equipo o en el USB desde el que se ejecuta. El
proyecto no opera ningún servidor y no recibe dato alguno de sus usuarios.

### Qué lee del equipo

Nombre y modelo del equipo, versión de Windows, estado de los discos
(SMART), registros de eventos de Windows, volcados de pantallazo azul,
configuración de red, y lista de controladores y servicios.

### Los reportes que genera

Se guardan **solo en disco local o en el USB**, en `Reportes/<EQUIPO>/`, en
HTML y JSON. Contienen datos identificables del equipo analizado: nombre,
número de serie, modelo. **Quien los comparta debe tenerlo en cuenta.** El
programa nunca los transmite por su cuenta.

### Las únicas conexiones de red que hace

El diagnóstico de red necesita comprobar si hay conexión, y para eso tiene
que intentar conectarse. Son estas y ninguna más:

| Destino | Para qué |
|---|---|
| La puerta de enlace de la red local | Comprobar que el router responde |
| `1.1.1.1:443` y `8.8.8.8:53` | Distinguir "sin internet" de "DNS caído" |
| Resolución DNS de `cloudflare.com` y `msftconnecttest.com` | Comprobar que los nombres se traducen |

No se envía ningún dato en esas comprobaciones: solo se mira si la conexión
se establece. Se pueden evitar por completo con `--quick`.

### Cambios en el equipo

El escaneo es **de solo lectura**. Ninguna comprobación modifica nada.

Las reparaciones (`--fix`) sí modifican el sistema, y por eso:

- Nunca se aplican solas: hay que confirmar cada una escribiendo `s`
- Se muestra antes qué comando se va a ejecutar y sobre qué
- Si no hay terminal interactiva, no se aplica nada
- La simulación es el comportamiento por defecto

### Desinstalación

InyaguiDiag es portable: no se instala. Borrar el archivo lo elimina por
completo. No escribe en el registro de Windows, no crea servicios ni tareas
programadas, y no deja archivos fuera de su propia carpeta.

## Reportar un problema de seguridad

Abrir una incidencia en
https://github.com/Ruben716/InyaguiDiag/issues

Si el problema es sensible, indicarlo sin dar detalles públicos y se
acordará un canal privado.
