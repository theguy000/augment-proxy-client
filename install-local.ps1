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
$InstallPath = "C:\Program Files\AIProxy"
$LocalBinaryPath = "C:\Users\i\git\augment-proxy-client\binaries\windows\proxy_client.exe"
$LocalCertPath = "C:\Users\i\git\augment-proxy-client\certs\mitmproxy-ca-cert.pem"

# Configuration Constants
$ServiceName = "ai-proxy"
$ServiceDisplayName = "ai-proxy"
$ServiceDescription = "Local proxy client for Augment AI"
$ProxyPort_Local = 3128
$NssmVersion = "2.24"
$LogRotationBytes = 1048576  # 1 MB

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
    # Clean up any stray files in installation directory
    Remove-Item "$InstallPath\*.zip" -Force -ErrorAction SilentlyContinue -Confirm:$false
    Remove-Item "$InstallPath\nssm-temp" -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false
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

    # Stop and remove proxy service
    try {
        Remove-ProxyService
    } catch {
        Write-ColorOutput "Error during service cleanup: $($_.Exception.Message)" "Warn"
    }

    # Remove installation directory
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

<#
.SYNOPSIS
    Checks and ensures required Windows services are running.
.DESCRIPTION
    Verifies that essential Windows services required for network connectivity
    and proxy functionality are running. Attempts to start them if stopped.
#>
function Test-WindowsServiceDependencies {
    Write-ColorOutput "Checking Windows service dependencies..." "Info"

    # List of critical services that might affect proxy functionality
    $criticalServices = @(
        @{ Name = "Dnscache"; DisplayName = "DNS Client"; Required = $true },
        @{ Name = "NlaSvc"; DisplayName = "Network Location Awareness"; Required = $true },
        @{ Name = "Netman"; DisplayName = "Network Connections"; Required = $true }
    )

    $allServicesOk = $true

    foreach ($svc in $criticalServices) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            
            if (-not $service) {
                Write-ColorOutput "Service '$($svc.DisplayName)' ($($svc.Name)) not found" "Warn"
                if ($svc.Required) {
                    $allServicesOk = $false
                }
                continue
            }

            if ($service.Status -eq "Running") {
                Write-ColorOutput "Service '$($svc.DisplayName)' is running" "Info"
            } else {
                Write-ColorOutput "Service '$($svc.DisplayName)' is $($service.Status)" "Warn"
                
                if ($svc.Required -and $service.Status -eq "Stopped") {
                    try {
                        Write-ColorOutput "Attempting to start '$($svc.DisplayName)'..." "Info"
                        Start-Service -Name $svc.Name -ErrorAction Stop
                        Start-Sleep -Seconds 2
                        
                        $service = Get-Service -Name $svc.Name
                        if ($service.Status -eq "Running") {
                            Write-ColorOutput "Service '$($svc.DisplayName)' started successfully" "Success"
                        } else {
                            Write-ColorOutput "Failed to start '$($svc.DisplayName)' - Status: $($service.Status)" "Warn"
                            $allServicesOk = $false
                        }
                    } catch {
                        Write-ColorOutput "Could not start '$($svc.DisplayName)': $($_.Exception.Message)" "Warn"
                        Write-ColorOutput "You may need to start this service manually" "Warn"
                        if ($svc.Required) {
                            $allServicesOk = $false
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput "Error checking service '$($svc.DisplayName)': $($_.Exception.Message)" "Warn"
        }
    }

    # Check for HTTP service (WinHTTP) - optional but important for some proxy scenarios
    try {
        $httpService = Get-Service -Name "http" -ErrorAction SilentlyContinue
        if ($httpService) {
            if ($httpService.Status -ne "Running") {
                Write-ColorOutput "Windows HTTP service is $($httpService.Status) - this may affect proxy functionality" "Warn"
                
                # Check dependencies
                $httpConfig = sc.exe qc http 2>&1
                if ($httpConfig -match "WinQuic") {
                    Write-ColorOutput "HTTP service depends on WinQuic service" "Info"
                    $winQuicService = Get-Service -Name "WinQuic" -ErrorAction SilentlyContinue
                    if (-not $winQuicService) {
                        Write-ColorOutput "WARNING: WinQuic service not found - HTTP service may not start" "Warn"
                        Write-ColorOutput "This is usually not critical for standalone proxy clients" "Info"
                    } elseif ($winQuicService.Status -ne "Running") {
                        Write-ColorOutput "WinQuic service is $($winQuicService.Status)" "Warn"
                    }
                }
            } else {
                Write-ColorOutput "Windows HTTP service is running" "Info"
            }
        } else {
            Write-ColorOutput "Windows HTTP service not found (this is normal on some Windows versions)" "Info"
        }
    } catch {
        # HTTP service might not exist on all Windows versions - this is OK
    }

    if (-not $allServicesOk) {
        Write-ColorOutput "Some required services are not running - proxy functionality may be affected" "Warn"
        Write-ColorOutput "You may need to start these services manually or restart your computer" "Warn"
    } else {
        Write-ColorOutput "All critical service dependencies are satisfied" "Success"
    }

    return $allServicesOk
}

# Check for admin privileges - warn but continue for testing
if (-not (Test-Administrator)) {
    Write-ColorOutput "WARNING: This script should be run as Administrator for full functionality" "Warn"
    Write-ColorOutput "Some operations may fail without admin privileges" "Warn"
    # Continue anyway for testing
}

<#
.SYNOPSIS
    Stops and removes the proxy service if it exists.
.DESCRIPTION
    Centralized function to handle service cleanup.
    Stops the service first, then removes it, then kills any remaining processes.
#>
function Remove-ProxyService {
    try {
        # Check for both ai-proxy.exe (new) and nssm.exe (old) for backward compatibility
        $nssmPath = "$InstallPath\ai-proxy.exe"
        if (-not (Test-Path $nssmPath)) {
            $nssmPath = "$InstallPath\nssm.exe"
        }

        $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if ($existingService) {
            Write-ColorOutput "Found existing $ServiceName service (Status: $($existingService.Status))" "Info"

            # Stop the service first if it's running
            if ($existingService.Status -eq "Running") {
                Write-ColorOutput "Stopping service..." "Info"
                try {
                    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                    Write-ColorOutput "Service stopped" "Success"
                    Start-Sleep -Seconds 2
                } catch {
                    Write-ColorOutput "Failed to stop service gracefully: $($_.Exception.Message)" "Warn"
                }
            } else {
                Write-ColorOutput "Service is already stopped" "Info"
            }

            # Remove the service using NSSM or sc.exe
            Write-ColorOutput "Removing service..." "Info"
            if (Test-Path $nssmPath) {
                & $nssmPath remove $ServiceName confirm 2>$null | Out-Null
            } else {
                sc.exe delete $ServiceName 2>$null | Out-Null
            }

            Start-Sleep -Seconds 1
            Write-ColorOutput "Service removed successfully" "Success"
        } else {
            Write-ColorOutput "No existing $ServiceName service found" "Info"
        }

        # Kill any remaining proxy_client processes
        $proxyProcesses = Get-Process -Name "proxy_client" -ErrorAction SilentlyContinue
        if ($proxyProcesses) {
            Write-ColorOutput "Found $($proxyProcesses.Count) proxy_client process(es), stopping them..." "Info"

            foreach ($proc in $proxyProcesses) {
                try {
                    Write-ColorOutput "Stopping process ID: $($proc.Id)" "Info"
                    taskkill /F /PID $proc.Id 2>$null | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        Write-ColorOutput "Process $($proc.Id) stopped" "Success"
                    }
                } catch {
                    Write-ColorOutput "Failed to stop process $($proc.Id): $($_.Exception.Message)" "Warn"
                }
            }

            # Wait and verify all processes are stopped
            Start-Sleep -Seconds 2
            $remainingProcesses = Get-Process -Name "proxy_client" -ErrorAction SilentlyContinue
            if ($remainingProcesses) {
                Write-ColorOutput "Warning: $($remainingProcesses.Count) proxy_client process(es) still running" "Warn"
                throw "Failed to stop all proxy_client processes. Please manually stop them and try again."
            } else {
                Write-ColorOutput "All proxy_client processes stopped successfully" "Success"
            }
        } else {
            Write-ColorOutput "No proxy_client processes found" "Info"
        }

    } catch {
        Write-ColorOutput "Error during cleanup: $($_.Exception.Message)" "Error"
        throw
    }
}

# Install proxy client from local binary
function Install-ProxyClient {
    Write-ColorOutput "Installing proxy client from local binary..." "Info"

    try {
        # Stop any existing processes/services first
        Write-ColorOutput "Checking for existing installation..." "Info"
        Remove-ProxyService
        Start-Sleep -Milliseconds 500

        if (Test-Path $InstallPath) {
            Write-ColorOutput "Removing old installation..." "Info"
            Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }

        New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
        New-Item -ItemType Directory -Force -Path "$InstallPath\logs" | Out-Null

        # Add Windows Defender exclusion AFTER creating directory (only exclude installation path)
        if (Test-Administrator) {
            try {
                Add-MpPreference -ExclusionPath $InstallPath -ErrorAction SilentlyContinue
                Write-ColorOutput "Windows Defender exclusion added for installation directory" "Success"
            } catch {
                Write-ColorOutput "Could not add Defender exclusion: $($_.Exception.Message)" "Warn"
            }
        }

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
    $nssmPath = "$InstallPath\ai-proxy.exe"

    try {
        # Check Windows service dependencies before starting
        Test-WindowsServiceDependencies | Out-Null

        # Verify proxy client executable exists
        if (-not (Test-Path $binaryPath)) {
            throw "Proxy client executable not found at: $binaryPath (Exit Code: 101)"
        }

        Write-ColorOutput "Downloading NSSM (service wrapper)..." "Info"

        # Download NSSM directly to installation directory (already excluded from Defender)
        $nssmUrl = "https://nssm.cc/release/nssm-$NssmVersion.zip"
        $nssmZip = "$InstallPath\nssm.zip"
        $nssmExtract = "$InstallPath\nssm-temp"

        try {
            Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing
            Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force

            # Copy the appropriate architecture version and rename to ai-proxy.exe
            if ([Environment]::Is64BitOperatingSystem) {
                Copy-Item "$nssmExtract\nssm-$NssmVersion\win64\nssm.exe" -Destination $nssmPath -Force
            } else {
                Copy-Item "$nssmExtract\nssm-$NssmVersion\win32\nssm.exe" -Destination $nssmPath -Force
            }

            # Clean up NSSM temporary files
            Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
            Remove-Item $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue

            Write-ColorOutput "Service wrapper installed as ai-proxy.exe" "Success"
        } catch {
            throw "Failed to download NSSM: $_"
        }

        # Verify service wrapper exists after installation
        if (-not (Test-Path $nssmPath)) {
            throw "Service wrapper not found at: $nssmPath (Exit Code: 102)"
        }

        Write-ColorOutput "Creating Windows service..." "Info"

        # Service cleanup is handled by Remove-ProxyService which is called in Install-ProxyClient

        # Install service using NSSM
        Write-ColorOutput "Installing $ServiceName service with NSSM..." "Info"
        & $nssmPath install $ServiceName $binaryPath $ProxyUsername $ProxyPassword | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "NSSM install failed with exit code: $LASTEXITCODE"
        }

        # Configure service
        & $nssmPath set $ServiceName DisplayName $ServiceDisplayName | Out-Null
        & $nssmPath set $ServiceName Description $ServiceDescription | Out-Null
        & $nssmPath set $ServiceName Start SERVICE_AUTO_START | Out-Null
        & $nssmPath set $ServiceName AppStdout "$InstallPath\logs\stdout.log" | Out-Null
        & $nssmPath set $ServiceName AppStderr "$InstallPath\logs\stderr.log" | Out-Null
        & $nssmPath set $ServiceName AppRotateFiles 1 | Out-Null
        & $nssmPath set $ServiceName AppRotateBytes $LogRotationBytes | Out-Null

        Write-ColorOutput "Service configured successfully" "Success"

        # Start the service
        Write-ColorOutput "Starting $ServiceName service..." "Info"
        & $nssmPath start $ServiceName | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "NSSM start failed with exit code: $LASTEXITCODE (Exit Code: 103)"
        }

        Start-Sleep -Seconds 2

        # Verify service is running
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            throw "Service was not created (Exit Code: 104)"
        }

        if ($service.Status -ne "Running") {
            # Try to get log information
            $logPath = "$InstallPath\logs\stderr.log"
            if (Test-Path $logPath) {
                $logContent = Get-Content $logPath -Tail 20 -ErrorAction SilentlyContinue
                Write-ColorOutput "Error log contents:" "Warn"
                $logContent | ForEach-Object { Write-Host "  $_" }
            }
            throw "Service status: $($service.Status). Expected: Running (Exit Code: 105)"
        }

        Write-ColorOutput "$ServiceName service started successfully" "Success"

        # Test if proxy is listening on the configured port
        Start-Sleep -Seconds 1
        try {
            $testConnection = Test-NetConnection -ComputerName localhost -Port $ProxyPort_Local -WarningAction SilentlyContinue
            if ($testConnection.TcpTestSucceeded) {
                Write-ColorOutput "Proxy client is listening on port $ProxyPort_Local" "Success"
            } else {
                Write-ColorOutput "Warning: Proxy service is running but not listening on port $ProxyPort_Local" "Warn"
            }
        } catch {
            Write-ColorOutput "Could not test port $ProxyPort_Local : $($_.Exception.Message)" "Warn"
        }

    } catch {
        Write-ColorOutput "Failed to start proxy service: $_" "Error"
        Invoke-Rollback
    }
}

<#
.SYNOPSIS
    Configures VS Code to use the local proxy.
.DESCRIPTION
    Updates VS Code settings.json to route traffic through
    the local proxy. Creates a backup before modifying.
#>
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
        $proxyUrl = "http://localhost:$ProxyPort_Local"
        $settings | Add-Member -NotePropertyName "http.proxy" -NotePropertyValue $proxyUrl -Force
        $settings | Add-Member -NotePropertyName "http.proxyStrictSSL" -NotePropertyValue $false -Force

        # Save settings
        $settings | ConvertTo-Json -Depth 10 | Set-Content $settingsPath -Force

        Write-ColorOutput "VS Code settings updated (proxy: $proxyUrl)" "Success"
    } catch {
        Write-ColorOutput "Failed to update VS Code settings: $($_.Exception.Message)" "Warn"
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
Set-VSCodeProxy
Invoke-Cleanup

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  Service name: $ServiceName" -ForegroundColor White
Write-Host "  Local proxy: localhost:$ProxyPort_Local" -ForegroundColor White
Write-Host "  Remote proxy: ${ProxyHost}:${ProxyPort}" -ForegroundColor White
Write-Host "  Username: $ProxyUsername" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Restart VS Code" -ForegroundColor White
Write-Host "  2. The Augment extension will now work through the proxy" -ForegroundColor White
Write-Host ""
Write-Host "Troubleshooting:" -ForegroundColor Cyan
Write-Host "  Service name: $ServiceName" -ForegroundColor White
Write-Host "  Check service status: Get-Service $ServiceName" -ForegroundColor White
Write-Host "  Restart service: Restart-Service $ServiceName" -ForegroundColor White
Write-Host "  View logs: Get-Content '$InstallPath\logs\stderr.log' -Tail 50" -ForegroundColor White
Write-Host "  Installation path: $InstallPath" -ForegroundColor White
Write-Host ""

