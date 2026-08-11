<#
.SYNOPSIS
    Compila InyaguiDiag y arma el USB portable.

.DESCRIPTION
    Construye el ejecutable con el toolchain de Python 3.8 -- el unico que
    produce binarios capaces de arrancar en Windows 7 -- y despliega la
    estructura completa en la unidad indicada.

    La verificacion post-compilacion NO es opcional. El registro de
    colectores y reglas usa imports dinamicos que PyInstaller no ve; si el
    .spec queda incompleto, el .exe se construye SIN reglas y reporta "sin
    problemas" en cualquier maquina. Es un fallo silencioso, asi que el
    script cuenta las reglas del binario compilado y aborta si faltan.

.PARAMETER Usb
    Letra de la unidad destino, p.ej. F:. Si se omite, solo compila.

.PARAMETER Arch
    x64 (por defecto) o x86. Para Windows 7 de 32 bits hace falta x86.

.EXAMPLE
    .\build\build.ps1
    .\build\build.ps1 -Usb F: -Arch x64
#>
[CmdletBinding()]
param(
    [string]$Usb = "",
    [ValidateSet("x64", "x86")]
    [string]$Arch = "x64"
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$python = Join-Path $root ".toolchain\py38-$Arch\tools\python.exe"

# Minimo de reglas que debe reportar el binario compilado. Si baja de
# aqui, el descubrimiento dinamico se rompio.
$MIN_RULES = 15

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
function Ok($text)   { Write-Host "  [ok] $text"   -ForegroundColor Green }
function Die($text)  { Write-Host "  [X] $text"    -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------
Step "Comprobando el toolchain"

if (-not (Test-Path $python)) {
    Die @"
No existe $python

El toolchain de Python 3.8 no esta versionado; se regenera extrayendo los
paquetes nuget oficiales de la PSF. Ver docs\AUDITORIA-DEPENDENCIAS.md
"@
}
$ver = & $python --version 2>&1
if ($ver -notmatch "3\.8\.") {
    Die "Se esperaba Python 3.8 y se encontro: $ver. Compilar con otra version rompe Windows 7."
}
Ok "$ver ($Arch)"

# ---------------------------------------------------------------------
Step "Dependencias"
& $python -m pip install -r (Join-Path $root "requirements.txt") `
    -c (Join-Path $root "constraints-py38.txt") --quiet --disable-pip-version-check
& $python -m pip install "pyinstaller==5.13.2" --quiet --disable-pip-version-check
Ok "instaladas con las restricciones de 3.8"

# ---------------------------------------------------------------------
Step "Pruebas"
$env:PYTHONPATH = Join-Path $root "src"
& $python -m pytest (Join-Path $root "tests") -q
if ($LASTEXITCODE -ne 0) { Die "Las pruebas fallaron. No se compila sobre codigo roto." }
Ok "suite completa en verde"

# ---------------------------------------------------------------------
Step "Compilando"
Push-Location $root
try {
    & $python -m PyInstaller "build\inyaguidiag.spec" `
        --distpath "dist\$Arch" --workpath "build\tmp\$Arch" --noconfirm --clean
    if ($LASTEXITCODE -ne 0) { Die "PyInstaller fallo" }
} finally { Pop-Location }

$exe = Join-Path $root "dist\$Arch\InyaguiDiag.exe"
if (-not (Test-Path $exe)) { Die "No se genero el ejecutable" }
Ok ("InyaguiDiag.exe  {0:N1} MB" -f ((Get-Item $exe).Length / 1MB))

# ---------------------------------------------------------------------
Step "Verificando el binario compilado"

# Esta es la comprobacion que justifica el script entero.
$output = & $exe --list-checks 2>&1 | Out-String
$rules = ([regex]::Matches($output, '(?m)^\s{2}[A-Z]{3}-\d{3}')).Count
$collectors = ([regex]::Matches($output, '(?m)^\s{2}[a-z\-]+\s+->')).Count

if ($rules -lt $MIN_RULES) {
    Die @"
El ejecutable reporta solo $rules reglas (se esperaban >= $MIN_RULES).

El descubrimiento dinamico se rompio: PyInstaller no incluyo los modulos.
Revisa 'hiddenimports' en build\inyaguidiag.spec.

ESTO ES GRAVE: un binario asi no falla, simplemente no encuentra nada y
declara sano cualquier equipo.
"@
}
Ok "$collectors colectores y $rules reglas presentes en el binario"

& $exe --version | ForEach-Object { Ok $_ }

# ---------------------------------------------------------------------
if (-not $Usb) {
    Step "Listo"
    Write-Host "  Ejecutable en: $exe"
    Write-Host "  Para desplegar al USB:  .\build\build.ps1 -Usb F:"
    exit 0
}

Step "Desplegando en $Usb"

$drive = Get-PSDrive ($Usb.TrimEnd(':')) -ErrorAction SilentlyContinue
if (-not $drive) { Die "La unidad $Usb no existe" }

$target = Join-Path "$Usb\" "InyaguiDiag"
New-Item -ItemType Directory -Force -Path `
    $target, "$target\tools\x64", "$target\tools\x86", "$target\Reportes" | Out-Null

Copy-Item $exe (Join-Path $target "InyaguiDiag-$Arch.exe") -Force
Ok "ejecutable copiado"

# smartctl: sin el, el diagnostico de discos degrada a un booleano de WMI
foreach ($a in @("x64", "x86")) {
    $src = Join-Path $root "tools\$a\smartctl.exe"
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $target "tools\$a\") -Force
        Ok "smartctl $a"
    } else {
        Write-Host "  [!] falta tools\$a\smartctl.exe: SMART degradara" -ForegroundColor Yellow
    }
}

# Lanzador para el tecnico: doble clic y listo
@'
@echo off
title InyaguiDiag - Diagnostico de sistema
cd /d "%~dp0"
if exist "InyaguiDiag-x64.exe" ( set EXE=InyaguiDiag-x64.exe ) else ( set EXE=InyaguiDiag-x86.exe )
echo.
echo   Inyagui Solutions - InyaguiDiag
echo   ================================
echo.
echo   Analizando este equipo. Puede tardar un minuto.
echo.
"%EXE%" --verbose --open -o "%~dp0Reportes"
echo.
pause
'@ | Set-Content (Join-Path $target "Diagnosticar.bat") -Encoding ASCII
Ok "Diagnosticar.bat"

$free = [math]::Round($drive.Free / 1GB, 2)
Step "Completado"
Write-Host "  Destino     : $target"
Write-Host "  Libre en USB: $free GB"
