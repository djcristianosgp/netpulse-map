param(
  [string]$Version = "1.0.0",
  [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$BuildScript = Join-Path $Root "build.bat"
$DistDir = Join-Path $Root "dist"
$StagingDir = Join-Path $DistDir "staging"
$IssPath = Join-Path $Root "packaging\installer\NetPulse2D.iss"

# Normalize numeric A.B.C.D for Windows VersionInfoVersion
$NumericVersion = "1.0.0.0"
if ($Version -match "^(\d+)\.(\d+)\.(\d+)") {
  $NumericVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3]).0"
} elseif ($Version -match "^(\d+)\.(\d+)") {
  $NumericVersion = "$($Matches[1]).$($Matches[2]).0.0"
}

Write-Host "[1/5] Compilando C++20 (/O2) v$Version..."
& cmd /c "`"$BuildScript`" $Version"
if ($LASTEXITCODE -ne 0) { throw "Falha na compilacao C++20." }

Write-Host "[2/5] Executando testes nativos C++..."
$TestExe = Join-Path $Root "build\test_core.exe"
& $TestExe
if ($LASTEXITCODE -ne 0) { throw "Falha nos testes unitarios C++." }

Write-Host "[3/5] Preparando staging limpo em $StagingDir..."
if (Test-Path $DistDir) {
  Remove-Item -Recurse -Force $DistDir
}
New-Item -ItemType Directory -Force -Path $StagingDir | Out-Null

Copy-Item (Join-Path $Root "build\netpulse.exe") -Destination $StagingDir
Copy-Item (Join-Path $Root "static") -Destination (Join-Path $StagingDir "static") -Recurse
Copy-Item (Join-Path $Root "assets") -Destination (Join-Path $StagingDir "assets") -Recurse
Copy-Item (Join-Path $Root "README.md") -Destination $StagingDir

Write-Host "[4/5] Gerando pacote portatil ZIP..."
$PortableZip = Join-Path $DistDir "NetPulse2D-Portable-x64.zip"
Compress-Archive -Path (Join-Path $StagingDir "*") -DestinationPath $PortableZip -CompressionLevel Optimal

if (-not $SkipInstaller) {
  $IsccCandidates = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
  )
  $Iscc = $IsccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $Iscc) {
    $Cmd = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($Cmd) { $Iscc = $Cmd.Source }
  }
  if (-not $Iscc) {
    throw "Inno Setup 6 (ISCC.exe) nao encontrado. Instale com 'choco install innosetup' ou passe -SkipInstaller."
  }

  Write-Host "[5/5] Compilando instalador Inno Setup 6 (v$Version)..."
  & $Iscc "/DMyAppVersion=$Version" "/DMyAppNumericVersion=$NumericVersion" $IssPath
  if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar instalador Inno Setup." }
}

# Remove staging before generating checksums
Remove-Item -Recurse -Force $StagingDir

$ChecksumsFile = Join-Path $DistDir "checksums.txt"
$Artifacts = Get-ChildItem $DistDir -File | Where-Object { $_.Name -ne "checksums.txt" }
$Lines = foreach ($f in $Artifacts) {
  $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  "$hash  $($f.Name)"
}
$Lines | Set-Content -Path $ChecksumsFile -Encoding UTF8

Write-Host "Pacotes gerados em ${DistDir}:"
Get-ChildItem $DistDir -File | Format-Table Name, Length
