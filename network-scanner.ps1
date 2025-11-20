# UTF-8 with BOM
<#
.SYNOPSIS
    Network Security Scanner Tool - Educational Purposes Only
.DESCRIPTION
    PowerShell script for scanning local network and discovering devices and services
    For educational purposes only with explicit permission
.NOTES
    Author: Cybersecurity Team
    Version: 1.0
    Date: 2024
#>

# Color settings
$Host.UI.RawUI.ForegroundColor = "White"

function Show-Banner {
    Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║          Network Security Scanner Tool                   ║
║          Educational Purposes Only                       ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Get-LocalNetworkInfo {
    Write-Host "`n[*] Gathering local network information..." -ForegroundColor Yellow
    
    $networkInfo = @{
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
        Architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        IPAddresses = @()
        DefaultGateway = $null
    }
    
    # Collect IP information
    $adapters = Get-NetIPConfiguration | Where-Object {$_.IPv4Address -ne $null}
    foreach ($adapter in $adapters) {
        $networkInfo.IPAddresses += [PSCustomObject]@{
            InterfaceName = $adapter.InterfaceAlias
            IPv4Address = $adapter.IPv4Address.IPAddress
            SubnetMask = $adapter.IPv4Address.PrefixLength
        }
        if ($adapter.IPv4DefaultGateway) {
            $networkInfo.DefaultGateway = $adapter.IPv4DefaultGateway.NextHop
        }
    }
    
    return $networkInfo
}

function Get-NetworkDevices {
    Write-Host "`n[*] Scanning network devices..." -ForegroundColor Yellow
    
    $devices = @()
    
    # Use ARP to get connected devices
    $arpCache = Get-NetNeighbor | Where-Object {$_.State -ne "Unreachable"}
    
    foreach ($entry in $arpCache) {
        $device = [PSCustomObject]@{
            IPAddress = $entry.IPAddress
            MACAddress = $entry.LinkLayerAddress
            State = $entry.State
            InterfaceAlias = $entry.InterfaceAlias
        }
        $devices += $device
    }
    
    return $devices
}

function Test-DeviceConnectivity {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    
    Write-Host "[*] Testing connectivity to $IPAddress..." -ForegroundColor Yellow
    
    $pingResult = Test-Connection -ComputerName $IPAddress -Count 2 -Quiet
    
    if ($pingResult) {
        Write-Host "[+] Device $IPAddress is online" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] Device $IPAddress is offline" -ForegroundColor Red
        return $false
    }
}

function Test-CommonPorts {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    
    Write-Host "`n[*] Scanning common ports on $IPAddress..." -ForegroundColor Yellow
    
    $commonPorts = @{
        445 = "SMB/CIFS"
        3389 = "RDP"
        80 = "HTTP"
        443 = "HTTPS"
        22 = "SSH"
        21 = "FTP"
        135 = "RPC"
        139 = "NetBIOS"
    }
    
    $openPorts = @()
    
    foreach ($port in $commonPorts.Keys) {
        $result = Test-NetConnection -ComputerName $IPAddress -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            $service = $commonPorts[$port]
            Write-Host "[+] Port $port is open - $service" -ForegroundColor Green
            $openPorts += [PSCustomObject]@{
                Port = $port
                Service = $service
                Status = "Open"
            }
        }
    }
    
    if ($openPorts.Count -eq 0) {
        Write-Host "[-] No open ports found" -ForegroundColor Yellow
    }
    
    return $openPorts
}

function Get-SMBShares {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    
    Write-Host "`n[*] Checking SMB shares on $IPAddress..." -ForegroundColor Yellow
    
    try {
        $shares = net view \\$IPAddress 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Found shares:" -ForegroundColor Green
            Write-Host $shares
            return $shares
        } else {
            Write-Host "[-] Cannot access SMB shares" -ForegroundColor Yellow
            return $null
        }
    } catch {
        Write-Host "[-] Error connecting to $IPAddress" -ForegroundColor Red
        return $null
    }
}

function Export-Results {
    param (
        [Parameter(Mandatory=$true)]
        $Results
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = "network_scan_$timestamp.json"
    
    $Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $outputFile -Encoding UTF8
    
    Write-Host "`n[+] Results saved to: $outputFile" -ForegroundColor Green
}

# Main program
function Start-NetworkScan {
    Show-Banner
    
    Write-Host "`nWARNING: This tool is for educational purposes only" -ForegroundColor Red
    Write-Host "Make sure you have permission before scanning any network`n" -ForegroundColor Red
    
    $confirmation = Read-Host "Do you want to continue? (Y/N)"
    if ($confirmation -ne "Y" -and $confirmation -ne "y") {
        Write-Host "Cancelled" -ForegroundColor Yellow
        return
    }
    
    # Gather local device information
    $localInfo = Get-LocalNetworkInfo
    Write-Host "`n=== Local Device Information ===" -ForegroundColor Cyan
    Write-Host "Hostname: $($localInfo.Hostname)"
    Write-Host "Operating System: $($localInfo.OS)"
    Write-Host "Version: $($localInfo.OSVersion)"
    Write-Host "Architecture: $($localInfo.Architecture)"
    Write-Host "`nIP Addresses:"
    $localInfo.IPAddresses | Format-Table -AutoSize
    
    # Discover devices
    $devices = Get-NetworkDevices
    Write-Host "`n=== Discovered Devices ===" -ForegroundColor Cyan
    Write-Host "Number of devices: $($devices.Count)"
    $devices | Format-Table -AutoSize
    
    # Detailed scan (optional)
    $detailedScan = Read-Host "`nDo you want to perform a detailed scan? (Y/N)"
    if ($detailedScan -eq "Y" -or $detailedScan -eq "y") {
        $targetIP = Read-Host "Enter IP address for detailed scan"
        
        if (Test-DeviceConnectivity -IPAddress $targetIP) {
            $ports = Test-CommonPorts -IPAddress $targetIP
            $shares = Get-SMBShares -IPAddress $targetIP
            
            # Save results
            $results = @{
                Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                LocalInfo = $localInfo
                Devices = $devices
                DetailedScan = @{
                    TargetIP = $targetIP
                    OpenPorts = $ports
                    SMBShares = $shares
                }
            }
            
            Export-Results -Results $results
        }
    }
    
    Write-Host "`n[+] Scan completed!" -ForegroundColor Green
}

# Run the tool
Start-NetworkScan
