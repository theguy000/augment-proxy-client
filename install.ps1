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
    [string]$Version = "0.92.3"
)

$InstallerVersion = "1.0.8"  # Installer script version
$ErrorActionPreference = "Stop"
$GitHubRaw = "https://raw.githubusercontent.com/$GitHubRepo/main"

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

# Cleanup function
function Invoke-Cleanup {
    Write-ColorOutput "Cleaning up temporary files..." "Info"
    Remove-Item "$env:TEMP\cntlm*" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\mitmproxy-ca-cert.pem" -Force -ErrorAction SilentlyContinue
}

# Rollback function
function Invoke-Rollback {
    Write-ColorOutput "Installation failed. Rolling back..." "Error"
    
    # Stop and remove CNTLM service
    try {
        Stop-Service -Name "CNTLM" -ErrorAction SilentlyContinue
        sc.exe delete "CNTLM" | Out-Null
    } catch {}
    
    # Remove CNTLM installation
    Remove-Item "C:\Program Files\CNTLM" -Recurse -Force -ErrorAction SilentlyContinue
    
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

# Detect architecture
function Get-SystemArchitecture {
    if ([Environment]::Is64BitOperatingSystem) {
        return "x64"
    } else {
        return "x86"
    }
}

# Download and install CNTLM
function Install-CNTLM {
    Write-ColorOutput "Downloading CNTLM for Windows..." "Info"

    $installPath = "C:\Program Files\CNTLM"

    try {
        # Create installation directory
        New-Item -ItemType Directory -Force -Path $installPath | Out-Null

        # Download CNTLM binaries from GitHub
        $files = @("cntlm.exe", "cygwin1.dll", "cyggcc_s-1.dll", "cygstdc++-6.dll", "cygrunsrv.exe")

        foreach ($file in $files) {
            $fileUrl = "$GitHubRaw/binaries/windows/$file"
            $filePath = "$installPath\$file"

            Write-ColorOutput "Downloading $file..." "Info"
            Invoke-WebRequest -Uri $fileUrl -OutFile $filePath -UseBasicParsing
        }

        Write-ColorOutput "CNTLM downloaded successfully" "Success"
    } catch {
        Write-ColorOutput "Failed to download CNTLM: $_" "Error"
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

# Generate CNTLM configuration
function New-CNTLMConfig {
    Write-ColorOutput "Generating CNTLM configuration..." "Info"
    
    $templateUrl = "$GitHubRaw/templates/cntlm.conf.template"
    $configPath = "C:\Program Files\CNTLM\cntlm.conf"
    
    try {
        # Try to download template
        $template = (Invoke-WebRequest -Uri $templateUrl -UseBasicParsing).Content
        
        # Replace placeholders
        $config = $template -replace '{{PROXY_USERNAME}}', $ProxyUsername
        $config = $config -replace '{{PROXY_PASSWORD}}', $ProxyPassword
        $config = $config -replace '{{PROXY_HOST}}', $ProxyHost
        $config = $config -replace '{{PROXY_PORT}}', $ProxyPort
        
        Set-Content -Path $configPath -Value $config -Force
    } catch {
        Write-ColorOutput "Could not download template, creating config directly..." "Warn"
        
        # Fallback: create config directly
        $config = @"
# CNTLM Configuration for Augment Proxy
Listen 3128
Proxy ${ProxyHost}:${ProxyPort}
Username $ProxyUsername
Password $ProxyPassword
Domain
Auth Basic
Allow 127.0.0.1
Allow localhost
Deny 0/0
NoProxy localhost, 127.0.0.1, .local
ConnectTimeout 3600
SocketTimeout 3600
LogLevel 2
"@
        Set-Content -Path $configPath -Value $config -Force
    }
    
    Write-ColorOutput "CNTLM configuration created" "Success"
}

# Create and start CNTLM service
function Start-CNTLMService {
    Write-ColorOutput "Creating CNTLM Windows service..." "Info"
    
    $serviceName = "CNTLM"
    $binaryPath = "C:\Program Files\CNTLM\cntlm.exe"
    $configPath = "C:\Program Files\CNTLM\cntlm.conf"
    
    try {
        # Check if service already exists
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-ColorOutput "CNTLM service already exists, removing..." "Info"
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $serviceName | Out-Null
            Start-Sleep -Seconds 2
        }
        
        # Verify CNTLM executable exists
        if (-not (Test-Path $binaryPath)) {
            throw "CNTLM executable not found at: $binaryPath"
        }

        # Verify config file exists
        if (-not (Test-Path $configPath)) {
            throw "CNTLM config file not found at: $configPath"
        }

        # Test CNTLM executable first
        Write-ColorOutput "Testing CNTLM executable..." "Info"
        try {
            $testResult = & $binaryPath -h 2>&1 | Out-String

            # Ignore Cygwin FAST_CWD warning - it's harmless on newer Windows versions
            if ($testResult -match "find_fast_cwd: WARNING") {
                Write-ColorOutput "Cygwin compatibility warning detected (harmless)" "Warn"
            }

            Write-ColorOutput "CNTLM executable test passed" "Success"
        } catch {
            # If test fails, just warn but continue - the service start will be the real test
            Write-ColorOutput "CNTLM test warning: $_" "Warn"
        }

        # Add CNTLM directory to system PATH so DLLs can be found
        $installDir = Split-Path $binaryPath -Parent
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($currentPath -notlike "*$installDir*") {
            Write-ColorOutput "Adding CNTLM to system PATH..." "Info"
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$installDir", "Machine")
        }

        # Create new service using New-Service cmdlet
        Write-ColorOutput "Creating Windows service..." "Info"

        # Create service with New-Service (simpler and more reliable than sc.exe)
        try {
            New-Service -Name $serviceName `
                        -BinaryPathName "`"$binaryPath`" -c `"$configPath`"" `
                        -DisplayName "CNTLM Auth Proxy" `
                        -Description "Local proxy for Augment API authentication" `
                        -StartupType Manual `
                        -ErrorAction Stop | Out-Null

            Write-ColorOutput "Service created successfully" "Success"
        } catch {
            throw "Failed to create service: $_"
        }

        Write-ColorOutput "Service created, attempting to start..." "Info"

        # Start service with error handling
        try {
            Start-Service -Name $serviceName -ErrorAction Stop

            # Wait for service to start
            Start-Sleep -Seconds 3

            # Verify service is running
            $service = Get-Service -Name $serviceName
            if ($service.Status -ne "Running") {
                throw "Service status: $($service.Status)"
            }

            Write-ColorOutput "CNTLM service started successfully" "Success"
        } catch {
            Write-ColorOutput "Service start failed: $_" "Warn"
            Write-ColorOutput "Attempting to run CNTLM as background process instead..." "Info"

            # Remove the failed service
            sc.exe delete $serviceName | Out-Null

            # Try to run CNTLM manually to see the error
            Write-ColorOutput "Testing CNTLM with config file..." "Info"
            $testOutput = & $binaryPath -c $configPath -v 2>&1 | Out-String
            Write-ColorOutput "CNTLM output: $testOutput" "Info"

            # Start CNTLM as a background process
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = $binaryPath
            $startInfo.Arguments = "-c `"$configPath`" -f"  # -f for foreground mode initially
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $false  # Show window for debugging
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true

            $process = [System.Diagnostics.Process]::Start($startInfo)

            if ($process) {
                Start-Sleep -Seconds 3

                # Read output
                $stdout = $process.StandardOutput.ReadToEnd()
                $stderr = $process.StandardError.ReadToEnd()

                if (-not $process.HasExited) {
                    Write-ColorOutput "CNTLM started as foreground process (PID: $($process.Id))" "Success"
                    Write-ColorOutput "STDOUT: $stdout" "Info"
                    Write-ColorOutput "STDERR: $stderr" "Info"
                    Write-ColorOutput "Note: CNTLM is running in foreground mode for debugging." "Warn"
                } else {
                    throw "CNTLM process exited immediately. Exit code: $($process.ExitCode)`nSTDOUT: $stdout`nSTDERR: $stderr"
                }
            } else {
                throw "Failed to start CNTLM process"
            }
        }
    } catch {
        Write-ColorOutput "Failed to start CNTLM: $_" "Error"
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
        Install-CNTLM
        Install-Certificate
        New-CNTLMConfig
        Start-CNTLMService
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
        Write-Host "  CNTLM running on: localhost:3128" -ForegroundColor White
        Write-Host "  Proxy server: ${ProxyHost}:${ProxyPort}" -ForegroundColor White
        Write-Host "  Username: $ProxyUsername" -ForegroundColor White
        Write-Host ""
        Write-Host "Troubleshooting:" -ForegroundColor Cyan
        Write-Host "  Check CNTLM status: Get-Service CNTLM" -ForegroundColor White
        Write-Host "  View event logs: Get-EventLog -LogName Application -Source CNTLM -Newest 10" -ForegroundColor White
        Write-Host "  Restart CNTLM: Restart-Service CNTLM" -ForegroundColor White
        Write-Host ""
    } catch {
        Write-ColorOutput "Installation failed: $_" "Error"
        Invoke-Rollback
    }
}

# Run main installation
Main

