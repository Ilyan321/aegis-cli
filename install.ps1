# Aegis CLI Universal Windows PowerShell Installer
# Usage: irm https://aegis.ilyankhan.tech/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "Ilyan321/aegis-cli"
$BinaryName = "aegis.exe"
$InstallDir = "$HOME\AppData\Local\Programs\aegis"

Write-Host "Installing Aegis CLI on Windows..." -ForegroundColor Cyan

# Check if Go toolchain is installed
if (Get-Command go -ErrorAction SilentlyContinue) {
    Write-Host "Go detected. Installing via go install..." -ForegroundColor Green
    go install "github.com/${Repo}/cmd/aegis@latest"
    Write-Host "Aegis installed successfully to $(go env GOPATH)\bin\aegis.exe" -ForegroundColor Green
    Write-Host "Run 'aegis --help' to get started." -ForegroundColor Yellow
    exit 0
}

# Determine Architecture
$Arch = "amd64"
if ([System.Environment]::Is64BitOperatingSystem -eq $false) {
    Write-Host "Error: 32-bit Windows is not supported." -ForegroundColor Red
    exit 1
}

$ReleaseUrl = "https://github.com/${Repo}/releases/latest/download/aegis_windows_${Arch}.zip"
$ZipPath = "$env:TEMP\aegis_windows.zip"

Write-Host "Downloading Aegis from GitHub Releases..." -ForegroundColor Cyan
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $ReleaseUrl -OutFile $ZipPath -UseBasicParsing
} catch {
    Write-Host "Precompiled release not yet found. Please install Go (https://go.dev) or build from source:" -ForegroundColor Yellow
    Write-Host "   git clone https://github.com/${Repo}.git; cd aegis-cli; go build -o bin/aegis.exe cmd/aegis/main.go" -ForegroundColor Yellow
    exit 1
}

# Create installation directory
if (!(Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "Extracting executable..." -ForegroundColor Cyan
Expand-Archive -Path $ZipPath -DestinationPath "$env:TEMP\aegis_extracted" -Force
Copy-Item -Path "$env:TEMP\aegis_extracted\*\$BinaryName" -Destination "$InstallDir\$BinaryName" -Force
Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\aegis_extracted" -Recurse -Force -ErrorAction SilentlyContinue

# Ensure InstallDir is in User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", [EnvironmentVariableTarget]::User)
    $env:Path += ";$InstallDir"
    Write-Host "Added $InstallDir to User PATH." -ForegroundColor Green
}

Write-Host "`nAegis CLI installed successfully!" -ForegroundColor Green
Write-Host "Run 'aegis --help' to get started." -ForegroundColor Yellow
