<#
.SYNOPSIS
    Construye una imagen WinPE minima con InyaguiDiag incorporado.

.DESCRIPTION
    Este es el entorno de rescate: se arranca desde el USB en un equipo que
    NO bootea, se monta su disco y se analiza en modo OFFLINE.

    POR QUE UN WinPE PROPIO Y NO UNA SUITE DE TERCEROS
    --------------------------------------------------
    Hiren's BootCD PE pesa poco mas de 3 GB porque trae mas de cien
    herramientas. Un WinPE minimo ronda los 400-600 MB, y le agregamos
    solo lo nuestro. La diferencia decide si el USB de 4 GB alcanza.

    POR QUE WinPE Y NO UN LINUX LIVE
    --------------------------------
    WinPE lee NTFS de forma nativa y corre el MISMO ejecutable que el modo
    online, sin recompilar. Con Linux habria que mantener dos binarios y
    pelear con permisos y drivers.

.NOTES
    REQUISITOS QUE ESTE SCRIPT NO PUEDE RESOLVER SOLO:

      1. Windows ADK + complemento "Windows PE". Descarga de Microsoft.
         Instalar el ADK PRIMERO y el complemento WinPE DESPUES: el
         instalador del complemento espera encontrar el ADK y falla si no.
      2. Privilegios de ADMINISTRADOR. DISM monta y modifica una imagen
         del sistema; no hay forma de hacerlo como usuario normal.

.PARAMETER Arch
    amd64 (por defecto) o x86. Para equipos viejos de 32 bits hace falta x86.

.PARAMETER Output
    Carpeta de trabajo. Necesita ~2 GB libres durante el proceso.

.PARAMETER Iso
    Si se indica, genera tambien un .iso listo para Ventoy.

.EXAMPLE
    .\build\winpe.ps1 -Arch amd64 -Iso
#>
[CmdletBinding()]
param(
    [ValidateSet("amd64", "x86")]
    [string]$Arch = "amd64",
    [string]$Output = "$env:TEMP\InyaguiPE",
    [switch]$Iso
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

function Step($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "  [ok] $t"   -ForegroundColor Green }
function Die($t)  { Write-Host "  [X] $t"    -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------
Step "Requisitos"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "Hace falta ejecutar esta consola como Administrador. DISM monta una imagen del sistema y no hay atajo."
}
Ok "administrador"

$adk = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit"
$peRoot = Join-Path $adk "Windows Preinstallation Environment"
if (-not (Test-Path $peRoot)) {
    Die @"
No se encontro el complemento Windows PE del ADK en:
  $peRoot

Descarga desde Microsoft e instala EN ESTE ORDEN:
  1. Windows ADK               (marcar 'Deployment Tools')
  2. Windows PE add-on for ADK
"@
}
Ok "ADK con complemento WinPE"

$copype = Join-Path $adk "Deployment Tools\DandISetUpEnv.bat"
if (-not (Test-Path $copype)) { Die "Faltan las Deployment Tools del ADK" }

# El ADK moderno ya no trae WinPE de 32 bits. Microsoft lo retiro a partir
# del ADK para Windows 11 22H2. Comprobarlo aqui evita que el script muera
# a mitad del proceso con un error de copype que no explica nada.
if ($Arch -eq "x86" -and -not (Test-Path (Join-Path $peRoot "x86"))) {
    Die @"
Este ADK no incluye WinPE de 32 bits.

Microsoft lo retiro desde el ADK para Windows 11 22H2. La ultima version
con WinPE x86 es el complemento del ADK para Windows 10 2004:
  https://go.microsoft.com/fwlink/?linkid=2120253

ANTES DE INSTALARLO, comprueba si de verdad hace falta. WinPE amd64
arranca en CUALQUIER procesador de 64 bits, sin importar que el Windows
instalado sea de 32. Solo los equipos con procesador de 32 bits reales
--Pentium 4, Atom antiguos-- necesitan WinPE x86.

Para el resto, usa:  .\build\winpe.ps1 -Arch amd64
"@
}

# El .exe de InyaguiDiag debe existir: WinPE sin la herramienta no sirve
$exe = Join-Path $root "dist\$(if ($Arch -eq 'amd64') {'x64'} else {'x86'})\InyaguiDiag.exe"
if (-not (Test-Path $exe)) {
    Die "Falta $exe. Ejecuta primero:  .\build\build.ps1 -Arch $(if ($Arch -eq 'amd64') {'x64'} else {'x86'})"
}
Ok "ejecutable presente"

# ---------------------------------------------------------------------
Step "Creando el entorno base"

if (Test-Path $Output) {
    Write-Host "  limpiando $Output"
    cmd /c rmdir /s /q "$Output" 2>$null
}

# copype prepara el arbol de trabajo de WinPE
$copypeCmd = Join-Path $peRoot "copype.cmd"
cmd /c "`"$copypeCmd`" $Arch `"$Output`"" | Out-Null
if (-not (Test-Path "$Output\media\sources\boot.wim")) { Die "copype fallo" }
Ok "arbol WinPE creado"

$mount = Join-Path $Output "mount"
$wim = Join-Path $Output "media\sources\boot.wim"

# ---------------------------------------------------------------------
Step "Montando la imagen"
Dism /Mount-Image /ImageFile:"$wim" /Index:1 /MountDir:"$mount" | Out-Null
if ($LASTEXITCODE -ne 0) { Die "No se pudo montar boot.wim" }
Ok "montada en $mount"

try {
    # -----------------------------------------------------------------
    Step "Agregando componentes"

    # Solo lo imprescindible. Cada paquete suma peso, y el presupuesto de
    # 3 GB del USB manda.
    #   WMI        : el ejecutable consulta WMI incluso en modo offline
    #   Scripting  : necesario para WMI
    #   StorageWMI : clases de disco
    $pkgPath = Join-Path $peRoot "$Arch\WinPE_OCs"
    foreach ($pkg in @("WinPE-WMI", "WinPE-Scripting", "WinPE-StorageWMI")) {
        $cab = Join-Path $pkgPath "$pkg.cab"
        if (Test-Path $cab) {
            Dism /Image:"$mount" /Add-Package /PackagePath:"$cab" | Out-Null
            $lang = Join-Path $pkgPath "es-es\${pkg}_es-es.cab"
            if (Test-Path $lang) {
                Dism /Image:"$mount" /Add-Package /PackagePath:"$lang" | Out-Null
            }
            Ok $pkg
        } else {
            Write-Host "  [!] no se encontro $pkg" -ForegroundColor Yellow
        }
    }

    # -----------------------------------------------------------------
    Step "Incorporando InyaguiDiag"

    $dest = Join-Path $mount "InyaguiDiag"
    New-Item -ItemType Directory -Force -Path $dest, "$dest\tools\x64", "$dest\tools\x86" | Out-Null
    Copy-Item $exe (Join-Path $dest "InyaguiDiag.exe") -Force
    foreach ($a in @("x64", "x86")) {
        $src = Join-Path $root "tools\$a\smartctl.exe"
        if (Test-Path $src) { Copy-Item $src "$dest\tools\$a\" -Force }
    }
    Ok "herramienta incorporada"

    # -----------------------------------------------------------------
    Step "Configurando el arranque"

    # startnet.cmd es lo primero que corre WinPE. wpeinit inicializa red y
    # dispositivos; sin el no hay letras de unidad asignadas y el
    # diagnostico offline no encontraria ningun disco.
    @'
@echo off
wpeinit
cd /d X:\InyaguiDiag
echo.
echo   ============================================
echo    Inyagui Solutions - Entorno de rescate
echo   ============================================
echo.
echo   Buscando instalaciones de Windows en los discos...
echo.
InyaguiDiag.exe --detect
echo.
echo   Para analizar un disco:
echo      InyaguiDiag.exe --offline D:\Windows
echo.
cmd /k
'@ | Set-Content (Join-Path $mount "Windows\System32\startnet.cmd") -Encoding ASCII
    Ok "startnet.cmd"

} finally {
    Step "Desmontando"
    Dism /Unmount-Image /MountDir:"$mount" /Commit | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] fallo al desmontar. Limpieza manual:" -ForegroundColor Yellow
        Write-Host "      Dism /Cleanup-Wim" -ForegroundColor Yellow
        exit 1
    }
    Ok "desmontada y guardada"
}

$size = [math]::Round((Get-Item $wim).Length / 1MB, 0)
Ok "boot.wim: $size MB"

# ---------------------------------------------------------------------
if ($Iso) {
    Step "Generando ISO"
    $isoPath = Join-Path $root "dist\InyaguiPE-$Arch.iso"
    $makeMedia = Join-Path $peRoot "MakeWinPEMedia.cmd"
    cmd /c "`"$makeMedia`" /ISO `"$Output`" `"$isoPath`"" | Out-Null
    if (Test-Path $isoPath) {
        Ok ("{0}  {1:N0} MB" -f $isoPath, ((Get-Item $isoPath).Length / 1MB))
        Write-Host "`n  Copia esta ISO a la raiz del USB con Ventoy instalado." -ForegroundColor Cyan
    } else {
        Die "MakeWinPEMedia fallo"
    }
}

Step "Listo"
