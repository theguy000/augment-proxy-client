#
# Augment Proxy - One-Line Installer for Windows
# Usage: iwr -useb https://raw.githubusercontent.com/USER/augment-proxy-client/main/install.ps1 -OutFile install.ps1; .\install.ps1 -ProxyUsername "username" -ProxyPassword "password"
#

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ProxyUsername,

    [Parameter(Mandatory=$true, Position=1)]
    [string]$ProxyPassword,

    [string]$ProxyHost = "proxy.ai-proxy.space",
    [string]$ProxyPort = "6969",
    [string]$GitHubRepo = "theguy000/augment-proxy-client",
    [string]$Version = "0.92.3",
    [switch]$NoRollback  # Debug flag to prevent rollback
)

$InstallerVersion = "1.0.16"  # Installer script version
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
        # Check if running as administrator
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($isAdmin) {
            Add-MpPreference -ExclusionPath $Path -ErrorAction SilentlyContinue
            Write-ColorOutput "Windows Defender exclusion added successfully" "Success"
        } else {
            Write-ColorOutput "Not running as administrator - skipping Defender exclusion (may cause issues)" "Warn"
        }
    } catch {
        Write-ColorOutput "Could not add Defender exclusion: $($_.Exception.Message)" "Warn"
    }
}

# Cleanup function
function Invoke-Cleanup {
    Write-ColorOutput "Cleaning up temporary files..." "Info"
    Remove-Item "$env:TEMP\3proxy*" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\mitmproxy-ca-cert.pem" -Force -ErrorAction SilentlyContinue
}

# Rollback function
function Invoke-Rollback {
    if ($NoRollback) {
        Write-ColorOutput "Installation failed. NoRollback flag set - keeping files for debugging..." "Warn"
        Write-ColorOutput "3proxy files are in: $InstallPath" "Info"
        Write-ColorOutput "Config file: $InstallPath\3proxy.cfg" "Info"
        Invoke-Cleanup
        exit 1
    }

    Write-ColorOutput "Installation failed. Rolling back..." "Error"

    # Stop and remove 3proxy service
    try {
        Stop-Service -Name "3proxy" -ErrorAction SilentlyContinue
        sc.exe delete "3proxy" | Out-Null
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

# Download and install 3proxy
function Install-3Proxy {
    Write-ColorOutput "Downloading 3proxy for Windows..." "Info"

    try {
        # Add Windows Defender exclusions BEFORE downloading
        Add-DefenderExclusion -Path $InstallPath
        Add-DefenderExclusion -Path $env:TEMP

        # Create installation directory
        New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null

        # Download 3proxy lite version (smaller, no x64 requirement)
        $proxyUrl = "https://github.com/3proxy/3proxy/releases/download/0.9.4/3proxy-0.9.4.zip"
        $zipPath = "$env:TEMP\3proxy.zip"
        $extractPath = "$env:TEMP\3proxy"

        Write-ColorOutput "Downloading 3proxy lite version..." "Info"
        Invoke-WebRequest -Uri $proxyUrl -OutFile $zipPath -UseBasicParsing

        Write-ColorOutput "Extracting 3proxy..." "Info"
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

        # Find and copy 3proxy.exe (it's in bin/Win32 for lite version)
        $exePath = Get-ChildItem -Path $extractPath -Filter "3proxy.exe" -Recurse | Select-Object -First 1
        if ($exePath) {
            Copy-Item $exePath.FullName -Destination "$InstallPath\3proxy.exe" -Force
            Write-ColorOutput "3proxy installed successfully" "Success"
        } else {
            throw "Could not find 3proxy.exe in downloaded archive"
        }

        # Cleanup temp files
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue

    } catch {
        Write-ColorOutput "Failed to download 3proxy: $_" "Error"
        Invoke-Rollback
    }
}

# Install mitmproxy certificate
function Install-Certificate {
    Write-ColorOutput "Downloading mitmproxy certificate..." "Info"
    
    $certUrl = "$GitHubRaw/certs/mitmproxy-ca-cert.pem"
    $certPath = "$env:TEMP\mitmproxy-ca-cert.pem"
    
    try {
        Invoke-WebRequest -Uri $certUrl -OutFile $certPath -UseBasicParsing
        
        Write-ColorOutput "Installing certificate to Trusted Root Certification Authorities..." "Info"
        
        # Import certificate to user's trusted root store
        certutil -addstore -user "Root" $certPath | Out-Null
        
        Write-ColorOutput "Certificate installed successfully" "Success"
    } catch {
        Write-ColorOutput "Failed to install certificate: $_" "Error"
        Invoke-Rollback
    }
}

# Generate 3proxy configuration
function New-3ProxyConfig {
    Write-ColorOutput "Generating 3proxy configuration..." "Info"

    $configPath = "$InstallPath\3proxy.cfg"

    try {
        # Create 3proxy config with Basic authentication support
        $config = @"
# 3proxy configuration for Augment Proxy
# Logging
log

# Local proxy on port 3128
proxy -p3128

# Access control - allow all from localhost
allow 127.0.0.1

# Parent proxy with Basic authentication (must come after allow)
parent 1000 http ${ProxyHost} ${ProxyPort} ${ProxyUsername} ${ProxyPassword}
"@
        Set-Content -Path $configPath -Value $config -Force
        Write-ColorOutput "3proxy configuration created" "Success"
    } catch {
        Write-ColorOutput "Failed to create config: $_" "Error"
        Invoke-Rollback
    }
}

# Create and start 3proxy service
function Start-3ProxyService {
    Write-ColorOutput "Installing 3proxy Windows service..." "Info"

    $binaryPath = "$InstallPath\3proxy.exe"
    $configPath = "$InstallPath\3proxy.cfg"

    try {
        # Verify 3proxy executable exists
        if (-not (Test-Path $binaryPath)) {
            throw "3proxy executable not found at: $binaryPath"
        }

        # Verify config file exists
        if (-not (Test-Path $configPath)) {
            throw "3proxy config file not found at: $configPath"
        }

        # Use 3proxy's built-in service installer
        Write-ColorOutput "Installing service using 3proxy --install..." "Info"

        # Change to install directory so 3proxy can find config
        Push-Location $InstallPath

        try {
            # Run 3proxy --install to install as Windows service
            $installOutput = & $binaryPath --install 2>&1 | Out-String

            Write-ColorOutput "Service installation output: $installOutput" "Info"

            # Wait for service to be registered
            Start-Sleep -Seconds 2

            # Check if service exists
            $service = Get-Service -Name "3proxy" -ErrorAction SilentlyContinue
            if (-not $service) {
                throw "Service was not created by 3proxy --install"
            }

            Write-ColorOutput "3proxy service installed successfully" "Success"

        } finally {
            Pop-Location
        }

        Write-ColorOutput "Starting 3proxy service..." "Info"

        # Start service with error handling
        try {
            Start-Service -Name "3proxy" -ErrorAction Stop

            # Wait for service to start
            Start-Sleep -Seconds 3

            # Verify service is running
            $service = Get-Service -Name "3proxy"
            if ($service.Status -ne "Running") {
                throw "Service status: $($service.Status)"
            }

            Write-ColorOutput "3proxy service started successfully" "Success"
        } catch {
            Write-ColorOutput "Service start failed: $_" "Warn"
            Write-ColorOutput "Attempting to run 3proxy as background process instead..." "Info"

            # Remove the failed service
            sc.exe delete "3proxy" | Out-Null

            # Start 3proxy as a background process using Start-Process
            Write-ColorOutput "Starting 3proxy as background process..." "Info"

            # Use Start-Process with -PassThru to get the process object
            $process = Start-Process -FilePath $binaryPath `
                                     -ArgumentList "`"$configPath`"" `
                                     -WindowStyle Hidden `
                                     -PassThru `
                                     -ErrorAction Stop

            if ($process) {
                Start-Sleep -Seconds 3

                # Check if process is still running
                $process.Refresh()
                if (-not $process.HasExited) {
                    Write-ColorOutput "3proxy started as background process (PID: $($process.Id))" "Success"
                    Write-ColorOutput "Note: 3proxy will stop when you log out. To make it persistent, fix the service issue." "Warn"

                    # Test if 3proxy is listening on port 3128
                    Start-Sleep -Seconds 2
                    try {
                        $testConnection = Test-NetConnection -ComputerName localhost -Port 3128 -WarningAction SilentlyContinue
                        if ($testConnection.TcpTestSucceeded) {
                            Write-ColorOutput "3proxy is listening on port 3128" "Success"
                        } else {
                            Write-ColorOutput "Warning: 3proxy process is running but not listening on port 3128" "Warn"
                        }
                    } catch {
                        Write-ColorOutput "Could not test port 3128: $_" "Warn"
                    }
                } else {
                    throw "3proxy process exited immediately. Exit code: $($process.ExitCode)"
                }
            } else {
                throw "Failed to start 3proxy process"
            }
        }
    } catch {
        Write-ColorOutput "Failed to start 3proxy: $_" "Error"
        Invoke-Rollback
    }
}

# Configure VS Code
function Set-VSCodeProxy {
    Write-ColorOutput "Configuring VS Code..." "Info"
    
    $settingsPath = "$env:APPDATA\Code\User\settings.json"
    
    if (-not (Test-Path $settingsPath)) {
        Write-ColorOutput "VS Code settings file not found at: $settingsPath" "Warn"
        Write-ColorOutput "Please manually configure VS Code with:" "Warn"
        Write-Host '  "http.proxy": "http://localhost:3128"' -ForegroundColor Yellow
        Write-Host '  "http.proxyStrictSSL": false' -ForegroundColor Yellow
        return
    }
    
    try {
        # Backup original settings
        Copy-Item $settingsPath "${settingsPath}.backup" -Force
        
        # Read current settings
        $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
        
        # Update proxy settings
        $settings | Add-Member -NotePropertyName "http.proxy" -NotePropertyValue "http://localhost:3128" -Force
        $settings | Add-Member -NotePropertyName "http.proxyStrictSSL" -NotePropertyValue $false -Force
        
        # Save updated settings
        $settings | ConvertTo-Json -Depth 100 | Set-Content $settingsPath -Force
        
        Write-ColorOutput "VS Code configured (backup saved to ${settingsPath}.backup)" "Success"
    } catch {
        Write-ColorOutput "Failed to configure VS Code: $_" "Warn"
        Write-ColorOutput "Please manually add to VS Code settings:" "Warn"
        Write-Host '  "http.proxy": "http://localhost:3128"' -ForegroundColor Yellow
        Write-Host '  "http.proxyStrictSSL": false' -ForegroundColor Yellow
    }
}

# Test proxy connectivity
function Test-ProxyConnectivity {
    Write-ColorOutput "Testing proxy connectivity..." "Info"
    
    try {
        $proxyUri = "http://localhost:3128"
        $testUrl = "http://example.com"
        
        $response = Invoke-WebRequest -Uri $testUrl -Proxy $proxyUri -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        
        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 403) {
            Write-ColorOutput "Proxy is responding correctly" "Success"
            return $true
        }
    } catch {
        Write-ColorOutput "Proxy connectivity test failed: $_" "Warn"
        Write-ColorOutput "This may be normal if the proxy only allows specific domains" "Info"
        return $false
    }
}

# Main installation flow
function Main {
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Augment Proxy - One-Line Installer" -ForegroundColor Cyan
    Write-Host "Version: $InstallerVersion" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        Install-3Proxy
        Install-Certificate
        New-3ProxyConfig
        Start-3ProxyService
        Set-VSCodeProxy
        Test-ProxyConnectivity
        Invoke-Cleanup

        Write-Host ""
        Write-Host "=========================================" -ForegroundColor Green
        Write-Host " Installation Complete!" -ForegroundColor Green
        Write-Host "=========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Cyan
        Write-Host "1. Restart VS Code" -ForegroundColor White
        Write-Host "2. The Augment extension will now work through the proxy" -ForegroundColor White
        Write-Host ""
        Write-Host "Configuration:" -ForegroundColor Cyan
        Write-Host "  3proxy running on: localhost:3128" -ForegroundColor White
        Write-Host "  Proxy server: ${ProxyHost}:${ProxyPort}" -ForegroundColor White
        Write-Host "  Username: $ProxyUsername" -ForegroundColor White
        Write-Host ""
        Write-Host "Troubleshooting:" -ForegroundColor Cyan
        Write-Host "  Check service status: Get-Service 3proxy" -ForegroundColor White
        Write-Host "  Restart service: Restart-Service 3proxy" -ForegroundColor White
        Write-Host "  Config file: $InstallPath\3proxy.cfg" -ForegroundColor White
        Write-Host ""
    } catch {
        Write-ColorOutput "Installation failed: $_" "Error"
        Invoke-Rollback
    }
}

# Run main installation
Main

