@echo off
setlocal EnableExtensions

cd /d "%~dp0"

where git >nul 2>&1
if errorlevel 1 (
  echo [ERRO] Git nao encontrado no PATH.
  exit /b 1
)

for /f "delims=" %%B in ('git rev-parse --abbrev-ref HEAD 2^>nul') do set "CURRENT_BRANCH=%%B"
if not defined CURRENT_BRANCH (
  echo [ERRO] Este diretorio nao e um repositorio Git valido.
  exit /b 1
)

echo ============================================================
echo  NetPulse 2D - Gerador de Tag e Push de Release
echo ============================================================
echo  Branch atual : %CURRENT_BRANCH%

echo [1/5] Sincronizando tags remotas com origin...
git fetch --tags origin <nul >nul 2>&1

for /f "delims=" %%T in ('powershell -NoProfile -InputFormat None -Command "$tags = git tag -l 'v*' | ForEach-Object { if ($_ -match '^v(\d+)\.(\d+)\.(\d+)$') { [PSCustomObject]@{ Tag=$_; Maj=[int]$matches[1]; Min=[int]$matches[2]; Pat=[int]$matches[3] } } } | Sort-Object Maj,Min,Pat -Descending; if ($tags) { $tags[0].Tag } else { 'v0.0.0' }"') do set "LATEST_TAG=%%T"

for /f "tokens=1,2,3 delims=." %%A in ("%LATEST_TAG:v=%") do (
  set "CUR_MAJ=%%A"
  set "CUR_MIN=%%B"
  set "CUR_PAT=%%C"
)

set /a NEXT_PAT=CUR_PAT + 1
set /a NEXT_MIN=CUR_MIN + 1
set /a NEXT_MAJ=CUR_MAJ + 1

set "VER_PATCH=%CUR_MAJ%.%CUR_MIN%.%NEXT_PAT%"
set "VER_MINOR=%CUR_MAJ%.%NEXT_MIN%.0"
set "VER_MAJOR=%NEXT_MAJ%.0.0"

echo  Ultima tag   : %LATEST_TAG%
echo.

set "DRY_RUN=0"
set "ARG=%~1"
if /I "%~2"=="--dry-run" set "DRY_RUN=1"
if /I "%ARG%"=="--dry-run" (
  set "DRY_RUN=1"
  set "ARG="
)

set "TARGET_VER="
if not defined ARG goto :prompt_version

if /I "%ARG%"=="patch" set "TARGET_VER=%VER_PATCH%"
if /I "%ARG%"=="minor" set "TARGET_VER=%VER_MINOR%"
if /I "%ARG%"=="major" set "TARGET_VER=%VER_MAJOR%"
if not defined TARGET_VER set "TARGET_VER=%ARG:v=%"
goto :validate_version

:prompt_version
echo Escolha a proxima versao:
echo   [1] Patch : v%VER_PATCH%
echo   [2] Minor : v%VER_MINOR% ^(recomendado para novas funcionalidades^)
echo   [3] Major : v%VER_MAJOR%
echo   [4] Informar versao manualmente
echo.
set "CHOICE="
set /p "CHOICE=Opcao [1-4] (padrao 2): "
if defined CHOICE set "CHOICE=%CHOICE: =%"
if not defined CHOICE set "CHOICE=2"
if "%CHOICE%"=="1" set "TARGET_VER=%VER_PATCH%"
if "%CHOICE%"=="2" set "TARGET_VER=%VER_MINOR%"
if "%CHOICE%"=="3" set "TARGET_VER=%VER_MAJOR%"
if "%CHOICE%"=="4" set /p "TARGET_VER=Digite a versao (ex: 2.1.0 ou 2.1.0-beta.1): "

:validate_version
if not defined TARGET_VER (
  echo [ERRO] Nenhuma versao selecionada.
  exit /b 1
)

set "TARGET_VER=%TARGET_VER:v=%"
set "TARGET_VER=%TARGET_VER: =%"
powershell -NoProfile -InputFormat None -Command "if ('%TARGET_VER%' -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') { exit 1 }"
if errorlevel 1 (
  echo [ERRO] Formato de versao invalido: "%TARGET_VER%". Use SemVer X.Y.Z ^(ex: 2.1.0^).
  exit /b 1
)

set "NEXT_TAG=v%TARGET_VER%"
echo  Tag alvo     : %NEXT_TAG%
echo.

git rev-parse -q --verify "refs/tags/%NEXT_TAG%" >nul 2>&1
if not errorlevel 1 (
  echo [ERRO] A tag "%NEXT_TAG%" ja existe localmente.
  exit /b 1
)

git ls-remote --exit-code --tags origin "refs/tags/%NEXT_TAG%" >nul 2>&1
if not errorlevel 1 (
  echo [ERRO] A tag "%NEXT_TAG%" ja existe no remoto origin.
  exit /b 1
)

echo [2/5] Verificando working tree...
set "HAS_CHANGES="
for /f "delims=" %%S in ('git status --porcelain') do set "HAS_CHANGES=1"

if not defined HAS_CHANGES goto :ready_to_push

echo [AVISO] Existem alteracoes nao commitadas no repositorio:
git status -s
echo.
if "%DRY_RUN%"=="1" (
  echo [DRY-RUN] Simulacao encerrada antes de commit/tag/push.
  exit /b 0
)

set "DO_COMMIT="
set /p "DO_COMMIT=Deseja fazer git add -A e commit antes de gerar a tag? (S/N): "
if /I not "%DO_COMMIT%"=="S" (
  echo [CANCELADO] Faca o commit das alteracoes antes de gerar a tag.
  exit /b 1
)

set "COMMIT_MSG="
set /p "COMMIT_MSG=Mensagem do commit (padrao: chore(release): %NEXT_TAG%): "
if not defined COMMIT_MSG set "COMMIT_MSG=chore(release): %NEXT_TAG%"
git add -A
if errorlevel 1 exit /b 1
git commit -m "%COMMIT_MSG%"
if errorlevel 1 exit /b 1

:ready_to_push
if "%DRY_RUN%"=="1" (
  echo [DRY-RUN] Tag calculada: %NEXT_TAG% na branch %CURRENT_BRANCH%. Nenhuma alteracao realizada.
  exit /b 0
)

echo.
set "CONFIRM="
set /p "CONFIRM=Confirmar criacao da tag %NEXT_TAG% e push para origin (%CURRENT_BRANCH% + %NEXT_TAG%)? (S/N): "
if /I not "%CONFIRM%"=="S" (
  echo [CANCELADO] Operacao cancelada pelo usuario.
  exit /b 1
)

echo [3/5] Enviando commits da branch %CURRENT_BRANCH% para origin...
git push origin "%CURRENT_BRANCH%"
if errorlevel 1 (
  echo [ERRO] Falha ao fazer push da branch %CURRENT_BRANCH%.
  exit /b 1
)

echo [4/5] Criando tag anotada %NEXT_TAG%...
git tag -a "%NEXT_TAG%" -m "Release %NEXT_TAG%"
if errorlevel 1 (
  echo [ERRO] Falha ao criar a tag %NEXT_TAG%.
  exit /b 1
)

echo [5/5] Enviando tag %NEXT_TAG% para origin...
git push origin "%NEXT_TAG%"
if errorlevel 1 (
  echo [ERRO] Falha ao enviar a tag %NEXT_TAG% para origin.
  exit /b 1
)

echo.
echo ============================================================
echo  SUCESSO! Tag %NEXT_TAG% criada e enviada para origin.
echo  O workflow release.yml do GitHub Actions ira compilar
echo  o instalador e publicar a release automaticamente.
echo ============================================================
exit /b 0
