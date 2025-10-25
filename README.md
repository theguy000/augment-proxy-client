# Augment Proxy Client

Client installation scripts and binaries for setting up CNTLM proxy to use with Augment VS Code extension.

##  Quick Installation

### Windows
```powershell
iwr -useb https://raw.githubusercontent.com/theguy000/augment-proxy-client/main/install.ps1 | iex -Args "YOUR_USERNAME","YOUR_PASSWORD"
```

### macOS / Linux
```bash
curl -fsSL https://raw.githubusercontent.com/theguy000/augment-proxy-client/main/install.sh | bash -s YOUR_USERNAME YOUR_PASSWORD
```

**Get your credentials from the [Augment Proxy Dashboard](https://dashboard.ai-proxy.space)**

##  What This Does

The installation script automatically:

1.  Downloads and installs CNTLM proxy
2.  Installs mitmproxy SSL certificates to system trust store
3.  Configures CNTLM with your credentials
4.  Sets up VS Code proxy settings
5.  Starts CNTLM as a system service

**Installation time:** ~2 minutes

##  Why CNTLM?

VS Code extensions cannot send Proxy-Authorization headers due to browser security restrictions. CNTLM is a local proxy that:
- Runs on your machine (localhost:3128)
- Accepts connections from VS Code
- Automatically injects proxy authentication headers
- Forwards requests to the Augment proxy

##  Troubleshooting

### Check CNTLM Status

**Windows:**
```powershell
Get-Service CNTLM
```

**macOS:**
```bash
sudo launchctl list | grep cntlm
```

**Linux:**
```bash
sudo systemctl status cntlm
```

### Test Proxy
```bash
curl -x http://localhost:3128 http://example.com
```

##  Repository Structure

```
augment-proxy-client/
 README.md
 install.sh              # Unix installer
 install.ps1             # Windows installer
 binaries/               # Pre-compiled CNTLM binaries
 certs/                  # mitmproxy certificates
 templates/              # Configuration templates
```

##  Support

For issues, visit the [main repository](https://github.com/theguy000/augment-proxy) or contact your administrator.

##  License

MIT License
