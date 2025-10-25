#
# Augment Proxy - Local Installer for Windows (using local binary)
# This script uses the local proxy_client.exe binary instead of downloading from GitHub
#

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ProxyUsername,

    [Parameter(Mandatory=$true, Position=1)]
    [string]$ProxyPassword,

    [string]$ProxyHost = "proxy.ai-proxy.space",
    [string]$ProxyPort = "6969",
    [switch]$NoRollback
)

$InstallerVersion = "3.0.0-local"
$ErrorActionPreference = "Stop"
$InstallPath = "C:\Program Files\AugmentProxy"
$LocalBinaryPath = "C:\Users\i\git\augment-proxy-client\binaries\windows\proxy_client.exe"
$LocalCertPath = "C:\Users\i\git\augment-proxy-client\certs\mitmproxy-ca-cert.pem"

# Log file for debugging
$LogFile = "C:\Users\i\git\augment-proxy-client\install.log"

# Colors for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Type = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"

    # Write to log file
    Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue

    switch ($Type) {
        "Info"    { Write-Host "[INFO] $Message" -ForegroundColor Blue }
        "Success" { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
        "Warn"    { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "[ERROR] $Message" -ForegroundColor Red }
    }
}

# Cleanup function
function Invoke-Cleanup {
    Write-ColorOutput "Cleaning up temporary files..." "Info"
    Remove-Item "$env:TEMP\proxy_client.exe" -Force -ErrorAction SilentlyContinue -Confirm:$false
    Remove-Item "$env:TEMP\mitmproxy-ca-cert.pem" -Force -ErrorAction SilentlyContinue
}

# Rollback function
function Invoke-Rollback {
    if ($NoRollback) {
        Write-ColorOutput "Installation failed. NoRollback flag set - keeping files for debugging..." "Warn"
        Write-ColorOutput "Proxy files are in: $InstallPath" "Info"
        Invoke-Cleanup
        exit 1
    }

    Write-ColorOutput "Installation failed. Rolling back..." "Error"

    try {
        $nssmPath = "$InstallPath\nssm.exe"
        if (Test-Path $nssmPath) {
            # Use NSSM to stop and remove service
            & $nssmPath stop AugmentProxy confirm 2>&1 | Out-Null
            & $nssmPath remove AugmentProxy confirm 2>&1 | Out-Null
        } else {
            # Fallback to traditional methods
            Stop-Service -Name "AugmentProxy" -ErrorAction SilentlyContinue
            sc.exe delete "AugmentProxy" 2>&1 | Out-Null
        }
    } catch {}

    Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue

    $settingsPath = "$env:APPDATA\Code\User\settings.json"
    if (Test-Path "${settingsPath}.backup") {
        Move-Item "${settingsPath}.backup" $settingsPath -Force
    }

    Invoke-Cleanup
    exit 1
}

# Check administrator privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check for admin privileges - warn but continue for testing
if (-not (Test-Administrator)) {
    Write-ColorOutput "WARNING: This script should be run as Administrator for full functionality" "Warn"
    Write-ColorOutput "Some operations may fail without admin privileges" "Warn"
    # Continue anyway for testing
}

# Install proxy client from local binary
function Install-ProxyClient {
    Write-ColorOutput "Installing proxy client from local binary..." "Info"

    try {
        Write-ColorOutput "Checking for existing installation..." "Info"
        Stop-Service -Name "AugmentProxy" -Force -ErrorAction SilentlyContinue
        Get-Process -Name "proxy_client" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        if (Test-Path $InstallPath) {
            Write-ColorOutput "Removing old installation..." "Info"
            Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }

        New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null

        if (-not (Test-Path $LocalBinaryPath)) {
            throw "Local binary not found at: $LocalBinaryPath"
        }

        Copy-Item $LocalBinaryPath -Destination "$InstallPath\proxy_client.exe" -Force
        Write-ColorOutput "Proxy client installed successfully" "Success"

    } catch {
        Write-ColorOutput "Failed to install proxy client: $_" "Error"
        Invoke-Rollback
    }
}

# Install certificate from local file
function Install-Certificate {
    Write-ColorOutput "Installing mitmproxy certificate..." "Info"

    try {
        if (-not (Test-Path $LocalCertPath)) {
            throw "Local certificate not found at: $LocalCertPath"
        }

        Write-ColorOutput "Installing certificate to Trusted Root Certification Authorities..." "Info"
        Import-Certificate -FilePath $LocalCertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

        Write-ColorOutput "Certificate installed successfully" "Success"
    } catch {
        Write-ColorOutput "Failed to install certificate: $_" "Error"
        Invoke-Rollback
    }
}

# Start proxy client service
function Start-ProxyService {
    Write-ColorOutput "Starting proxy client..." "Info"

    $binaryPath = "$InstallPath\proxy_client.exe"
    $nssmPath = "$InstallPath\nssm.exe"

    try {
        if (-not (Test-Path $binaryPath)) {
            throw "Proxy client executable not found at: $binaryPath"
        }

        Write-ColorOutput "Downloading NSSM (service wrapper)..." "Info"

        # Download NSSM
        $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
        $nssmZip = "$env:TEMP\nssm.zip"
        $nssmExtract = "$env:TEMP\nssm"

        try {
            Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing
            Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force

            # Copy the appropriate architecture version
            if ([Environment]::Is64BitOperatingSystem) {
                Copy-Item "$nssmExtract\nssm-2.24\win64\nssm.exe" -Destination $nssmPath -Force
            } else {
                Copy-Item "$nssmExtract\nssm-2.24\win32\nssm.exe" -Destination $nssmPath -Force
            }

            Write-ColorOutput "NSSM downloaded successfully" "Success"
        } catch {
            throw "Failed to download NSSM: $_"
        }

        Write-ColorOutput "Creating Windows service..." "Info"

        # First, check if service already exists and remove it
        $existingService = Get-Service -Name "AugmentProxy" -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-ColorOutput "Removing existing service..." "Info"
            Stop-Service -Name "AugmentProxy" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            & $nssmPath stop AugmentProxy confirm | Out-Null
            & $nssmPath remove AugmentProxy confirm | Out-Null
            Start-Sleep -Seconds 2
        }

        # Install service using NSSM
        Write-ColorOutput "Installing service with NSSM..." "Info"
        & $nssmPath install AugmentProxy $binaryPath $ProxyUsername $ProxyPassword | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "NSSM install failed with exit code: $LASTEXITCODE"
        }

        # Configure service
        & $nssmPath set AugmentProxy DisplayName "Augment Proxy Service" | Out-Null
        & $nssmPath set AugmentProxy Description "Local proxy client for Augment AI" | Out-Null
        & $nssmPath set AugmentProxy Start SERVICE_AUTO_START | Out-Null
        & $nssmPath set AugmentProxy AppStdout "$InstallPath\logs\stdout.log" | Out-Null
        & $nssmPath set AugmentProxy AppStderr "$InstallPath\logs\stderr.log" | Out-Null
        & $nssmPath set AugmentProxy AppRotateFiles 1 | Out-Null
        & $nssmPath set AugmentProxy AppRotateBytes 1048576 | Out-Null

        Write-ColorOutput "Service configured successfully" "Success"

        # Start the service
        Write-ColorOutput "Starting service..." "Info"
        & $nssmPath start AugmentProxy | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "NSSM start failed with exit code: $LASTEXITCODE"
        }

        Start-Sleep -Seconds 3

        # Verify service is running
        $service = Get-Service -Name "AugmentProxy" -ErrorAction SilentlyContinue
        if (-not $service) {
            throw "Service was not created"
        }

        if ($service.Status -ne "Running") {
            # Try to get log information
            $logPath = "$InstallPath\logs\stderr.log"
            if (Test-Path $logPath) {
                $logContent = Get-Content $logPath -Tail 20 -ErrorAction SilentlyContinue
                Write-ColorOutput "Error log:" "Warn"
                $logContent | ForEach-Object { Write-Host "  $_" }
            }
            throw "Service status: $($service.Status). Expected: Running"
        }

        Write-ColorOutput "Proxy client service started successfully" "Success"

    } catch {
        Write-ColorOutput "Failed to start proxy service: $_" "Error"
        Invoke-Rollback
    }
}

# Main installation
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Augment Proxy - Local Installer" -ForegroundColor Cyan
Write-Host "Version: $InstallerVersion" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

Install-ProxyClient
Install-Certificate
Start-ProxyService
Invoke-Cleanup

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  Proxy Host: $ProxyHost" -ForegroundColor White
Write-Host "  Proxy Port: $ProxyPort" -ForegroundColor White
Write-Host "  Username: $ProxyUsername" -ForegroundColor White
Write-Host ""
Write-Host "Troubleshooting:" -ForegroundColor Cyan
Write-Host "  Check service status: Get-Service AugmentProxy" -ForegroundColor White
Write-Host "  Restart service: Restart-Service AugmentProxy" -ForegroundColor White
Write-Host "  Installation path: $InstallPath" -ForegroundColor White
Write-Host ""

