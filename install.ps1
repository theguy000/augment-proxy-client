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

# Convert plain text password to SecureString for internal use
$SecureProxyPassword = ConvertTo-SecureString -String $ProxyPassword -AsPlainText -Force

# Script Constants
$InstallerVersion = "3.0.0"  # Installer script version (Python proxy client)
$ErrorActionPreference = "Stop"
$GitHubRaw = "https://raw.githubusercontent.com/$GitHubRepo/main"
$InstallPath = "C:\Program Files\AugmentProxy"

# Configuration Constants
$ServiceName = "ai-proxy"
$ServiceDisplayName = "AI Proxy Service"
$ServiceDescription = "Local proxy client for Augment AI"
$ProxyPort_Local = 3128
$NssmVersion = "2.24"
$LogRotationBytes = 1048576  # 1 MB
$MaxDownloadRetries = 3
$RetryDelaySeconds = 2

# Cache admin check result
$script:IsAdministrator = $null

<#
.SYNOPSIS
    Writes colored output messages with type prefixes.
.PARAMETER Message
    The message to display.
.PARAMETER Type
    The message type (Info, Success, Warn, Error).
#>
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

<#
.SYNOPSIS
    Tests if the current session has administrator privileges.
.DESCRIPTION
    Checks if the current user is running with administrator privileges.
    Result is cached in script scope to avoid redundant checks.
.OUTPUTS
    Boolean indicating administrator status.
#>
function Test-Administrator {
    if ($null -eq $script:IsAdministrator) {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $script:IsAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    return $script:IsAdministrator
}

<#
.SYNOPSIS
    Downloads a file with retry logic and progress indication.
.PARAMETER Url
    The URL to download from.
.PARAMETER Destination
    The local file path to save to.
.PARAMETER Description
    Description for progress bar.
.OUTPUTS
    Boolean indicating success.
#>
function Get-FileWithRetry {
    param(
        [string]$Url,
        [string]$Destination,
        [string]$Description = "Downloading file"
    )

    for ($i = 1; $i -le $MaxDownloadRetries; $i++) {
        try {
            Write-ColorOutput "$Description (attempt $i/$MaxDownloadRetries)..." "Info"

            # Use WebClient for progress support
            $webClient = New-Object System.Net.WebClient

            # Register progress event
            Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -SourceIdentifier WebClient.DownloadProgressChanged -Action {
                Write-Progress -Activity $Description -Status "Downloading..." -PercentComplete $EventArgs.ProgressPercentage
            } | Out-Null

            # Download file
            $webClient.DownloadFile($Url, $Destination)

            # Cleanup
            Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged -ErrorAction SilentlyContinue
            $webClient.Dispose()
            Write-Progress -Activity $Description -Completed

            if (Test-Path $Destination) {
                Write-ColorOutput "$Description completed successfully" "Success"
                return $true
            }
        } catch {
            Write-ColorOutput "Download attempt $i failed: $($_.Exception.Message)" "Warn"
            Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged -ErrorAction SilentlyContinue

            if ($i -lt $MaxDownloadRetries) {
                Write-ColorOutput "Retrying in $RetryDelaySeconds seconds..." "Info"
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }
    }

    throw "Failed to download from $Url after $MaxDownloadRetries attempts"
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
        $nssmPath = "$InstallPath\nssm.exe"
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

<#
.SYNOPSIS
    Adds Windows Defender exclusion for a path.
.PARAMETER Path
    The path to exclude from Windows Defender scanning.
#>
function Add-DefenderExclusion {
    param([string]$Path)

    Write-ColorOutput "Adding Windows Defender exclusion for $Path..." "Info"
    try {
        if (Test-Administrator) {
            Add-MpPreference -ExclusionPath $Path -ErrorAction SilentlyContinue
            Write-ColorOutput "Windows Defender exclusion added successfully" "Success"
        } else {
            Write-ColorOutput "Not running as administrator - skipping Defender exclusion" "Warn"
        }
    } catch {
        Write-ColorOutput "Could not add Defender exclusion: $($_.Exception.Message)" "Warn"
    }
}

<#
.SYNOPSIS
    Cleans up temporary files created during installation.
#>
function Invoke-Cleanup {
    Write-ColorOutput "Cleaning up temporary files..." "Info"
    Remove-Item "$env:TEMP\proxy_client.exe" -Force -ErrorAction SilentlyContinue -Confirm:$false
    Remove-Item "$env:TEMP\mitmproxy-ca-cert.pem" -Force -ErrorAction SilentlyContinue -Confirm:$false
    Remove-Item "$env:TEMP\nssm.zip" -Force -ErrorAction SilentlyContinue -Confirm:$false
    Remove-Item "$env:TEMP\nssm" -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false
}

<#
.SYNOPSIS
    Rolls back installation changes on failure.
.DESCRIPTION
    Removes installed files, services, and restores backups.
    Can be disabled with -NoRollback flag for debugging.
#>
function Invoke-Rollback {
    param([string]$ErrorMessage = "Unknown error")

    if ($NoRollback) {
        Write-ColorOutput "Installation failed: $ErrorMessage" "Error"
        Write-ColorOutput "NoRollback flag set - keeping files for debugging..." "Warn"
        Write-ColorOutput "Installation files are in: $InstallPath" "Info"
        Invoke-Cleanup
        exit 1
    }

    Write-ColorOutput "Installation failed: $ErrorMessage" "Error"
    Write-ColorOutput "Rolling back changes..." "Warn"

    # Stop and remove proxy service
    Remove-ProxyService

    # Remove installation directory
    Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue

    # Restore VS Code settings backup
    $settingsPath = "$env:APPDATA\Code\User\settings.json"
    if (Test-Path "${settingsPath}.backup") {
        Move-Item "${settingsPath}.backup" $settingsPath -Force
        Write-ColorOutput "VS Code settings restored from backup" "Info"
    }

    Invoke-Cleanup
    Write-ColorOutput "Rollback completed" "Info"
    exit 1
}

# Check administrator privileges
if (-not (Test-Administrator)) {
    Write-ColorOutput "This script requires administrator privileges" "Error"
    Write-ColorOutput "Please run PowerShell as Administrator and try again" "Warn"
    exit 1
}

# Security warning about credentials
Write-ColorOutput "WARNING: Credentials are passed as plain text arguments" "Warn"
Write-ColorOutput "Ensure you are running this script in a secure environment" "Warn"
Write-Host ""

<#
.SYNOPSIS
    Downloads and installs the proxy client and NSSM in parallel.
.DESCRIPTION
    Removes existing installations, downloads required binaries,
    and prepares the installation directory.
#>
function Install-ProxyClient {
    Write-ColorOutput "Preparing installation..." "Info"

    try {
        # Stop any existing processes/services first
        Write-ColorOutput "Checking for existing installation..." "Info"
        Remove-ProxyService
        Start-Sleep -Milliseconds 500

        # Add Windows Defender exclusions BEFORE downloading
        Add-DefenderExclusion -Path $InstallPath
        Add-DefenderExclusion -Path $env:TEMP

        # Remove old installation if exists
        Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue

        # Create installation directory and logs subdirectory
        New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
        New-Item -ItemType Directory -Force -Path "$InstallPath\logs" | Out-Null

        # Prepare download paths
        $proxyUrl = "$GitHubRaw/binaries/windows/proxy_client.exe"
        $tempExePath = "$env:TEMP\proxy_client.exe"
        $nssmUrl = "https://nssm.cc/release/nssm-$NssmVersion.zip"
        $nssmZip = "$env:TEMP\nssm.zip"
        $nssmExtract = "$env:TEMP\nssm"

        Write-ColorOutput "Downloading proxy client and NSSM in parallel..." "Info"

        # Download both files in parallel using background jobs
        $proxyJob = Start-Job -ScriptBlock {
            param($Url, $Dest, $MaxRetries, $RetryDelay)

            for ($i = 1; $i -le $MaxRetries; $i++) {
                try {
                    $webClient = New-Object System.Net.WebClient
                    $webClient.DownloadFile($Url, $Dest)
                    $webClient.Dispose()
                    return $true
                } catch {
                    if ($i -lt $MaxRetries) {
                        Start-Sleep -Seconds $RetryDelay
                    } else {
                        throw
                    }
                }
            }
        } -ArgumentList $proxyUrl, $tempExePath, $MaxDownloadRetries, $RetryDelaySeconds

        $nssmJob = Start-Job -ScriptBlock {
            param($Url, $Dest, $MaxRetries, $RetryDelay)

            for ($i = 1; $i -le $MaxRetries; $i++) {
                try {
                    $webClient = New-Object System.Net.WebClient
                    $webClient.DownloadFile($Url, $Dest)
                    $webClient.Dispose()
                    return $true
                } catch {
                    if ($i -lt $MaxRetries) {
                        Start-Sleep -Seconds $RetryDelay
                    } else {
                        throw
                    }
                }
            }
        } -ArgumentList $nssmUrl, $nssmZip, $MaxDownloadRetries, $RetryDelaySeconds

        # Wait for both downloads with progress indication
        $completed = 0
        $total = 2
        while ((Get-Job -Id $proxyJob.Id, $nssmJob.Id | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
            $completedJobs = (Get-Job -Id $proxyJob.Id, $nssmJob.Id | Where-Object { $_.State -ne 'Running' }).Count
            if ($completedJobs -ne $completed) {
                $completed = $completedJobs
                Write-Progress -Activity "Downloading files" -Status "$completed of $total completed" -PercentComplete (($completed / $total) * 100)
            }
            Start-Sleep -Milliseconds 200
        }
        Write-Progress -Activity "Downloading files" -Completed

        # Check results and cleanup jobs
        $null = Receive-Job -Job $proxyJob -ErrorAction Stop
        $null = Receive-Job -Job $nssmJob -ErrorAction Stop
        Remove-Job -Job $proxyJob, $nssmJob

        Write-ColorOutput "Downloads completed successfully" "Success"

        # Verify and install proxy client
        if (-not (Test-Path $tempExePath)) {
            throw "Proxy client download failed - file not found"
        }
        Copy-Item $tempExePath -Destination "$InstallPath\proxy_client.exe" -Force
        Write-ColorOutput "Proxy client installed" "Success"

        # Extract and install NSSM
        if (-not (Test-Path $nssmZip)) {
            throw "NSSM download failed - file not found"
        }

        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force

        if ([Environment]::Is64BitOperatingSystem) {
            Copy-Item "$nssmExtract\nssm-$NssmVersion\win64\nssm.exe" -Destination "$InstallPath\nssm.exe" -Force
        } else {
            Copy-Item "$nssmExtract\nssm-$NssmVersion\win32\nssm.exe" -Destination "$InstallPath\nssm.exe" -Force
        }
        Write-ColorOutput "NSSM installed" "Success"

    } catch {
        Invoke-Rollback -ErrorMessage "Failed to install proxy client: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Downloads and installs the mitmproxy certificate.
.DESCRIPTION
    Downloads the certificate with retry logic and installs it
    to the Trusted Root Certification Authorities store.
#>
function Install-Certificate {
    Write-ColorOutput "Installing mitmproxy certificate..." "Info"

    try {
        $certUrl = "$GitHubRaw/certs/mitmproxy-ca-cert.pem"
        $certPath = "$env:TEMP\mitmproxy-ca-cert.pem"

        # Download with retry logic
        Get-FileWithRetry -Url $certUrl -Destination $certPath -Description "Downloading certificate"

        Write-ColorOutput "Installing certificate to Trusted Root Certification Authorities..." "Info"
        Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

        Write-ColorOutput "Certificate installed successfully" "Success"
    } catch {
        Invoke-Rollback -ErrorMessage "Failed to install certificate: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Configures and starts the proxy service using NSSM.
.DESCRIPTION
    Creates a Windows service using NSSM, configures it with
    appropriate settings, and verifies it's running correctly.
#>
function Start-ProxyService {
    Write-ColorOutput "Configuring proxy service..." "Info"

    $binaryPath = "$InstallPath\proxy_client.exe"
    $nssmPath = "$InstallPath\nssm.exe"

    try {
        # Verify executables exist
        if (-not (Test-Path $binaryPath)) {
            throw "Proxy client executable not found at: $binaryPath (Exit Code: 101)"
        }

        if (-not (Test-Path $nssmPath)) {
            throw "NSSM executable not found at: $nssmPath (Exit Code: 102)"
        }

        Write-ColorOutput "Creating Windows service..." "Info"

        # Install service using NSSM
        Write-ColorOutput "Installing $ServiceName service with NSSM..." "Info"
        # Convert SecureString to plain text for NSSM
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureProxyPassword)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        & $nssmPath install $ServiceName $binaryPath $ProxyUsername $plainPassword 2>$null | Out-Null

        # Clear the plain text password from memory
        $plainPassword = $null

        if ($LASTEXITCODE -ne 0) {
            throw "NSSM install failed with exit code: $LASTEXITCODE"
        }

        # Configure service
        & $nssmPath set $ServiceName DisplayName $ServiceDisplayName 2>$null | Out-Null
        & $nssmPath set $ServiceName Description $ServiceDescription 2>$null | Out-Null
        & $nssmPath set $ServiceName Start SERVICE_AUTO_START 2>$null | Out-Null
        & $nssmPath set $ServiceName AppStdout "$InstallPath\logs\stdout.log" 2>$null | Out-Null
        & $nssmPath set $ServiceName AppStderr "$InstallPath\logs\stderr.log" 2>$null | Out-Null
        & $nssmPath set $ServiceName AppRotateFiles 1 2>$null | Out-Null
        & $nssmPath set $ServiceName AppRotateBytes $LogRotationBytes 2>$null | Out-Null

        Write-ColorOutput "Service configured successfully" "Success"

        # Start the service
        Write-ColorOutput "Starting $ServiceName service..." "Info"
        & $nssmPath start $ServiceName 2>$null | Out-Null

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
        Invoke-Rollback -ErrorMessage "Failed to start proxy service: $($_.Exception.Message)"
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

<#
.SYNOPSIS
    Tests connectivity through the proxy.
.DESCRIPTION
    Attempts to connect to the Augment API through the local proxy
    to verify the setup is working correctly.
#>
function Test-ProxyConnectivity {
    Write-ColorOutput "Testing proxy connectivity..." "Info"

    try {
        $testUrl = "http://d18.api.augmentcode.com/health"
        $proxy = "http://localhost:$ProxyPort_Local"

        $null = Invoke-WebRequest -Uri $testUrl -Proxy $proxy -ProxyUseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop

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
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "Installation completed successfully!" -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Restart VS Code" -ForegroundColor White
    Write-Host "  2. The Augment extension will now work through the proxy" -ForegroundColor White
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Cyan
    Write-Host "  Service name: $ServiceName" -ForegroundColor White
    Write-Host "  Local proxy: localhost:$ProxyPort_Local" -ForegroundColor White
    Write-Host "  Remote proxy: ${ProxyHost}:${ProxyPort}" -ForegroundColor White
    Write-Host "  Username: $ProxyUsername" -ForegroundColor White
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Cyan
    Write-Host "  Check service status: Get-Service $ServiceName" -ForegroundColor White
    Write-Host "  Restart service: Restart-Service $ServiceName" -ForegroundColor White
    Write-Host "  View logs: Get-Content '$InstallPath\logs\stderr.log' -Tail 50" -ForegroundColor White
    Write-Host "  Installation path: $InstallPath" -ForegroundColor White
    Write-Host ""

} catch {
    Write-ColorOutput "Unexpected installation error: $($_.Exception.Message)" "Error"
    Invoke-Rollback -ErrorMessage $_.Exception.Message
}


