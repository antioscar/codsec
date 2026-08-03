# Build script para Analizador de Seguridad de Código
# Genera un ejecutable único con PyInstaller

param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Set-Location $projectRoot

if ($Clean) {
    Write-Host "[*] Limpiando builds anteriores..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue build, dist
    Remove-Item -Force -ErrorAction SilentlyContinue *.spec.bak
}

Write-Host "[*] Instalando/verificando PyInstaller..." -ForegroundColor Cyan
pip install pyinstaller 2>&1 | Out-Null
if (-not $?) {
    Write-Host "[!] Error instalando PyInstaller" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Construyendo ejecutable..." -ForegroundColor Cyan
python -m PyInstaller --clean --noconfirm analizador.spec 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Error en la construcción" -ForegroundColor Red
    exit 1
}

$exePath = Join-Path $projectRoot "dist\analizador-seguridad.exe"
if (Test-Path $exePath) {
    $size = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
    Write-Host "[OK] Ejecutable generado: $exePath ($size MB)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Para probar:" -ForegroundColor Cyan
    Write-Host "  .\dist\analizador-seguridad.exe --help" -ForegroundColor Gray
    Write-Host "  .\dist\analizador-seguridad.exe -p . --lang python --no-llm" -ForegroundColor Gray
} else {
    Write-Host "[!] Ejecutable no encontrado" -ForegroundColor Red
    exit 1
}
