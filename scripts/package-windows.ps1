$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$FrontendDir = Join-Path $RootDir "frontend"
$BackendDir = Join-Path $RootDir "backend"
$WwwrootDir = Join-Path $BackendDir "wwwroot"
$ArtifactsDir = Join-Path $RootDir "artifacts/windows"
$PublishDir = Join-Path $ArtifactsDir "SecureScope"
$ZipPath = Join-Path $ArtifactsDir "SecureScope-windows-x64.zip"

Remove-Item $WwwrootDir, $ArtifactsDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item $WwwrootDir, $PublishDir -ItemType Directory -Force | Out-Null

npm --prefix $FrontendDir run build
Copy-Item (Join-Path $FrontendDir "dist/*") $WwwrootDir -Recurse -Force

dotnet publish (Join-Path $BackendDir "SecureScope.Api.csproj") `
  --configuration Release `
  --runtime win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:AssemblyName=SecureScope `
  -p:DebugType=None `
  -p:DebugSymbols=false `
  --output $PublishDir

Copy-Item (Join-Path $PSScriptRoot "appsettings.LocalPackage.json") $PublishDir
Compress-Archive -Path $PublishDir -DestinationPath $ZipPath -Force

Write-Host ""
Write-Host "Created $ZipPath"
