# PowerShell equivalent of warp.sh
# Cloudflare WARP configuration generator with ZeroTrust support

param(
    [switch]$UseIPv4,
    [switch]$UseIPv6,
    [string]$TeamsToken,
    [string]$RefreshToken,
    [string]$ModelName = "rany2/warp.ps1",
    [string]$DeviceName,
    [switch]$ShowTrace,
    [alias("--help","-h","-?","/?")]
    [switch]$ShowHelp
)

function Show-Help {
    [CmdletBinding()]
    param()
    
    Write-Output @"
Usage: .\warp.ps1 [options]

Options:
  -UseIPv4          Use IPv4 for connections
  -UseIPv6          Use IPv6 for connections
  -TeamsToken       Teams JWT token for ZeroTrust authentication
  -RefreshToken     Refresh token (format: token,device_id,private_key)
  -ModelName        Model name (default: rany2/warp.ps1)
  -DeviceName       Device name
  -ShowTrace        Show Cloudflare trace and exit
  -ShowHelp         Show this help page
                    Aliases: --help, -h, -?, /?

Example for ZeroTrust enrollment:
  1. Visit https://<teams id>.cloudflareaccess.com/warp
  2. Authenticate through your organization
  3. Extract JWT token from page source or browser console:
     console.log(document.querySelector("meta[http-equiv='refresh']").content.split("=")[2])
  4. Run: .\warp.ps1 -TeamsToken eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.....
"@
}

function Get-RandomString {
    param([int]$Length = 32)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $result = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $result += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return $result
}

function Invoke-CFCurl {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [object]$Body
    )
    
    # Add default headers
    $Headers += @{
        'User-Agent' = '1.1.1.1/6.81'
        'CF-Client-Version' = 'a-6.81-2410012252.0'
        'Accept' = 'application/json; charset=UTF-8'
    }
    
    # Configure Invoke-RestMethod parameters
    $params = @{
        Uri = $Uri
        Method = $Method
        Headers = $Headers
        SkipCertificateCheck = $true
        ErrorAction = "Stop"
    }
    
    if ($Body) {
        $params.Body = $Body
        $params.ContentType = 'application/json'
    }
    
    try {
        return Invoke-RestMethod @params
    }
    catch {
        Write-Error "API request failed: $($_.Exception.Message)"
        exit 1
    }
}

function Convert-ClientIdToHex {
    param([string]$ClientIdBase64)
    
    $bytes = [Convert]::FromBase64String($ClientIdBase64)
    $hexArray = @()
    foreach ($byte in $bytes) {
        $hexArray += "{0:x2}" -f $byte
    }
    return $hexArray -join ""
}

# Show help if requested
if ($ShowHelp) {
    Show-Help
    exit 0
}

# Show trace if requested
if ($ShowTrace) {
    $trace = Invoke-CFCurl -Uri "https://www.cloudflare.com/cdn-cgi/trace"
    Write-Output $trace
    exit 0
}

# Generate WireGuard keys
# Note: This requires WireGuard tools to be installed on the system
try {
    $wgPrivateKey = (wg genkey 2>$null).Trim()
    if (-not $wgPrivateKey) {
        throw "Failed to generate WireGuard private key"
    }
    $wgPublicKey = (echo $wgPrivateKey | wg pubkey 2>$null).Trim()
    if (-not $wgPublicKey) {
        throw "Failed to generate WireGuard public key"
    }
} catch {
    Write-Error "WireGuard tools not found or failed to generate keys. Please install WireGuard tools."
    exit 1
}

# Cloudflare API base URL
$baseUrl = "https://api.cloudflareclient.com/v0a2483"

# Process refresh token if provided
if ($RefreshToken) {
    $tokenParts = $RefreshToken -split ','
    if ($tokenParts.Count -ne 3) {
        Write-Error "Invalid refresh token format. Expected: token,device_id,private_key"
        exit 1
    }
    
    $token = $tokenParts[0]
    $deviceId = $tokenParts[1]
    $wgPrivateKey = $tokenParts[2]
    $wgPublicKey = (echo $wgPrivateKey | wg pubkey 2>$null).Trim()
    
    # Get existing registration
    $headers = @{
        'Authorization' = "Bearer $token"
    }
    $reg = Invoke-CFCurl -Uri "$baseUrl/reg/$deviceId" -Headers $headers
} else {
    # Register new device
    $body = @{
        key = $wgPublicKey
        install_id = ""
        fcm_token = ""
        model = $ModelName
        serial_number = ""
        name = $DeviceName
        locale = "en_US"
    } | ConvertTo-Json
    
    $headers = @{ }
    if ($TeamsToken) {
        $headers['CF-Access-Jwt-Assertion'] = $TeamsToken
    }
    
    $reg = Invoke-CFCurl -Uri "$baseUrl/reg" -Method "POST" -Headers $headers -Body $body
}

# Extract configuration details
$peer = $reg.config.peers[0]
$interface = $reg.config.interface

$peerPublicKey = $peer.public_key
$endpointHost = $peer.endpoint.host
$endpointIPv4 = $peer.endpoint.v4
$endpointIPv6 = $peer.endpoint.v6
$addressIPv4 = $interface.addresses.v4
$addressIPv6 = $interface.addresses.v6
$clientIdBase64 = $reg.config.client_id

# Process client ID
$clientIdHex = Convert-ClientIdToHex -ClientIdBase64 $clientIdBase64
$clientIdBytes = [Convert]::FromBase64String($clientIdBase64)
$clientIdDec = "@(" + (($clientIdBytes | ForEach-Object { "0x$($_.ToString('x2'))" }) -join ", ") + ")"

# Extract credentials
$deviceId = $reg.id
$accountId = $reg.account.id
$accountLicense = if ($reg.account.license) { $reg.account.license } else { if ($TeamsToken) { "N/A" } else { "Unknown" } }
$token = if ($reg.token) { $reg.token } else { $token }

# Generate WireGuard configuration
@"
[Interface]
PrivateKey = $wgPrivateKey
#PublicKey = $wgPublicKey
Address = $addressIPv4/32, $addressIPv6/128
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280

# To refresh the config, run the following command:
# .\warp.ps1 -RefreshToken '$token,$deviceId,$wgPrivateKey'

# Cloudflare WARP specific variables
#CFDeviceId = $deviceId
#CFAccountId = $accountId
#CFAccountLicense = $accountLicense
#CFToken = $token
#CFClientIdB64 = $clientIdBase64
#CFClientIdHex = 0x$clientIdHex
#CFClientIdDec = $clientIdDec

[Peer]
PublicKey = $peerPublicKey
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
Endpoint = $($endpointIPv4 -replace ':.*', ''):2408
#Endpoint = $($endpointIPv6 -replace ':.*', ''):2408
#Endpoint = $($endpointHost -replace ':.*', ''):2408
"@