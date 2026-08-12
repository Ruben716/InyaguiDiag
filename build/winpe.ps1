<#
.SYNOPSIS
    Construye una ISO arrancable de WinPE para el rescate de equipos.

.DESCRIPTION
    Este es el entorno que se arranca en un equipo que NO bootea, para
    analizar su disco en modo OFFLINE.

    FUNCIONA SIN PRIVILEGIOS DE ADMINISTRADOR
    -----------------------------------------
    La via documentada por Microsoft (copype + MakeWinPEMedia) exige
    elevacion porque monta la imagen con DISM. Este script evita ese paso.

    El truco: `copype` falla al montar, pero ANTES de fallar ya copio la
    carpeta `media` completa con su `boot.wim` intacto. Ese boot.wim es el
    winpe.wim original del ADK, que arranca perfectamente. Solo falta
    empaquetarlo, y `oscdimg` --la herramienta que hay debajo de
    MakeWinPEMedia-- no necesita permisos especiales.

    Lo unico que se pierde sin montar es poder meter archivos DENTRO de la
    imagen. No hace falta: InyaguiDiag vive en la particion de datos del
    USB, y WinPE le asigna letra al arrancar.

    POR QUE NO HACE FALTA EL COMPONENTE WinPE-WMI
    ---------------------------------------------
    Ningun colector del modo OFFLINE usa WMI. `discovery.py` enumera las
    unidades con llamadas directas a kernel32 (GetLogicalDrives,
    GetDriveTypeW, GetVolumeInformation), y el resto solo lee archivos:
    .evtx, minidumps y hives del registro. Un WinPE limpio alcanza.

.PARAMETER Arch
    amd64 (por defecto) o arm64.

    NO existe x86: Microsoft retiro WinPE de 32 bits a partir del ADK para
    Windows 11 22H2. Casi nunca importa -- WinPE amd64 arranca en cualquier
    procesador de 64 bits aunque el Windows instalado sea de 32.

.PARAMETER Output
    Carpeta de trabajo. Necesita ~1 GB libre.

.EXAMPLE
    .\build\winpe.ps1
    .\build\winpe.ps1 -Arch amd64 -Output D:\temp\pe
#>
[CmdletBinding()]
param(
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64",
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
if (-not $Output) { $Output = Join-Path $root "build\pe-$Arch" }

function Step($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "  [ok] $t"   -ForegroundColor Green }
function Die($t)  { Write-Host "  [X] $t"    -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------
Step "Comprobando el ADK"

$adk = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit"
$peRoot = Join-Path $adk "Windows Preinstallation Environment"

if (-not (Test-Path $peRoot)) {
    Die @"
No se encontro el complemento Windows PE del ADK.

Descargar e instalar EN ESTE ORDEN:
  1. Windows ADK  (marcar solo 'Deployment Tools')
     https://go.microsoft.com/fwlink/?linkid=2289980
  2. Windows PE add-on
     https://go.microsoft.com/fwlink/?linkid=2289981
"@
}

# OJO con el nombre: es DandISetEnv.bat, NO DandISetUpEnv.bat. Casi toda la
# documentacion antigua cita el segundo, que no existe en el ADK actual.
# copype depende de las variables que define (%WinPERoot%, %OSCDImgRoot%) y
# sin ellas falla con un "processor architecture was not found" que no dice
# nada util.
$envSetup = Join-Path $adk "Deployment Tools\DandISetEnv.bat"
if (-not (Test-Path $envSetup)) { Die "Faltan las Deployment Tools del ADK" }

$srcWim = Join-Path $peRoot "$Arch\en-us\winpe.wim"
if (-not (Test-Path $srcWim)) {
    Die "El ADK no incluye WinPE para '$Arch'. Disponibles: " +
        ((Get-ChildItem $peRoot -Directory).Name -join ", ")
}
Ok "ADK con WinPE $Arch"

$oscdimg = Join-Path $adk "Deployment Tools\$Arch\Oscdimg\oscdimg.exe"
if (-not (Test-Path $oscdimg)) { Die "No se encontro oscdimg.exe" }
Ok "oscdimg"

# ---------------------------------------------------------------------
Step "Preparando el arbol de WinPE"

if (Test-Path $Output) { cmd /c rmdir /s /q "$Output" 2>$null }

# copype va a terminar en error al intentar montar la imagen (eso si pide
# administrador), pero para entonces ya dejo copiada la carpeta media con
# el boot.wim. Ese fallo es ESPERADO: se ignora y se comprueba el
# resultado, que es lo que importa.
$stage = Join-Path $env:TEMP "inyagui-copype.bat"
@"
@echo off
call "$envSetup"
copype $Arch "$Output"
"@ | Set-Content $stage -Encoding ASCII
cmd /c "`"$stage`"" 2>&1 | Out-Null
Remove-Item $stage -ErrorAction SilentlyContinue

$media = Join-Path $Output "media"
$wim = Join-Path $media "sources\boot.wim"
if (-not (Test-Path $wim)) {
    Die "copype no dejo el boot.wim. Revisa que el ADK este completo."
}
Ok ("boot.wim  {0:N0} MB" -f ((Get-Item $wim).Length / 1MB))
Ok ("media/    {0} archivos" -f (Get-ChildItem $media -Recurse -File).Count)

# ---------------------------------------------------------------------
Step "Archivos de arranque"

# copype normalmente los deja en fwfiles/, pero muere antes de llegar ahi.
# Se toman directamente del ADK.
$oscDir = Split-Path $oscdimg -Parent
$fw = Join-Path $Output "fwfiles"
New-Item -ItemType Directory -Force -Path $fw | Out-Null
foreach ($f in @("etfsboot.com", "efisys.bin")) {
    $src = Join-Path $oscDir $f
    if (-not (Test-Path $src)) { Die "Falta $f en $oscDir" }
    Copy-Item $src $fw -Force
}
Ok "etfsboot.com (BIOS) y efisys.bin (UEFI)"

# ---------------------------------------------------------------------
Step "Generando la ISO"

$iso = Join-Path $root "dist\InyaguiPE-$Arch.iso"
New-Item -ItemType Directory -Force -Path (Split-Path $iso -Parent) | Out-Null

# -bootdata:2#... declara DOS entradas de arranque: BIOS heredado
# (etfsboot) y UEFI (efisys). Con una sola, la ISO arranca nada mas en un
# tipo de equipo, y el parque de maquinas que atiende esta herramienta
# tiene de los dos.
#
# Se genera por .bat porque el paso de -bootdata desde PowerShell duplica
# las comillas y oscdimg responde "Could not open boot sector file".
$build = Join-Path $env:TEMP "inyagui-oscdimg.bat"
@"
@echo off
"$oscdimg" -m -o -u2 -udfver102 -bootdata:2#p0,e,b$fw\etfsboot.com#pEF,e,b$fw\efisys.bin "$media" "$iso"
"@ | Set-Content $build -Encoding ASCII
cmd /c "`"$build`"" 2>&1 | Select-Object -Last 3
Remove-Item $build -ErrorAction SilentlyContinue

if (-not (Test-Path $iso)) { Die "oscdimg no genero la ISO" }
Ok ("{0}  {1:N0} MB" -f $iso, ((Get-Item $iso).Length / 1MB))

# ---------------------------------------------------------------------
Step "Verificando"

# Se monta la ISO para confirmar que tiene los dos caminos de arranque.
# Una ISO que se genera sin error pero no arranca es peor que un fallo:
# solo se descubre delante del equipo averiado.
try {
    $img = Mount-DiskImage -ImagePath $iso -PassThru -ErrorAction Stop
    $letter = ($img | Get-Volume).DriveLetter
    $checks = @{
        "bootmgr"                = "arranque BIOS"
        "EFI\Boot\bootx64.efi"   = "arranque UEFI"
        "sources\boot.wim"       = "imagen del sistema"
        "Boot\BCD"               = "configuracion de arranque"
    }
    $bad = 0
    foreach ($k in $checks.Keys) {
        if (Test-Path "${letter}:\$k") { Ok $checks[$k] }
        else { Write-Host "  [X] falta $k ($($checks[$k]))" -ForegroundColor Red; $bad++ }
    }
    Dismount-DiskImage -ImagePath $iso | Out-Null
    if ($bad) { Die "La ISO esta incompleta" }
} catch {
    Write-Host "  [!] no se pudo montar para verificar: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------
Step "Listo"
Write-Host @"
  ISO: $iso

  Siguiente paso -- preparar el USB con Ventoy:

    1. Descargar Ventoy de https://www.ventoy.net/
    2. Instalarlo en el pendrive   << ESTO BORRA EL USB ENTERO
    3. Copiar la ISO a la raiz del USB
    4. Desplegar la parte portable:
         .\build\build.ps1 -Usb F: -Arch x64

  En el equipo averiado: arrancar desde el USB, elegir la ISO en el menu
  de Ventoy, y cuando cargue WinPE ejecutar la herramienta desde la
  particion de datos del pendrive:

    E:\InyaguiDiag\InyaguiDiag-x64.exe --detect

  (la letra cambia en WinPE; --detect encuentra el Windows averiado solo)
"@ -ForegroundColor Gray
