<#
.SYNOPSIS
    أداة فحص الشبكة التعليمية - للأغراض التعليمية فقط
.DESCRIPTION
    سكريبت PowerShell لفحص الشبكة المحلية واكتشاف الأجهزة والخدمات
    يستخدم فقط للأغراض التعليمية وبإذن صريح
.NOTES
    المؤلف: فريق الأمن السيبراني
    الإصدار: 1.0
    التاريخ: 2024
#>

# إعدادات الألوان
$Host.UI.RawUI.ForegroundColor = "White"

function Show-Banner {
    Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║          أداة فحص الشبكة التعليمية                      ║
║          Network Security Scanner Tool                   ║
║          للأغراض التعليمية فقط                          ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Get-LocalNetworkInfo {
    Write-Host "`n[*] جمع معلومات الشبكة المحلية..." -ForegroundColor Yellow
    
    $networkInfo = @{
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
        Architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        IPAddresses = @()
        DefaultGateway = $null
    }
    
    # جمع معلومات IP
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
    Write-Host "`n[*] فحص الأجهزة المتصلة بالشبكة..." -ForegroundColor Yellow
    
    $devices = @()
    
    # استخدام ARP للحصول على الأجهزة المتصلة
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
    
    Write-Host "[*] اختبار الاتصال بـ $IPAddress..." -ForegroundColor Yellow
    
    $pingResult = Test-Connection -ComputerName $IPAddress -Count 2 -Quiet
    
    if ($pingResult) {
        Write-Host "[+] الجهاز $IPAddress متصل" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] الجهاز $IPAddress غير متصل" -ForegroundColor Red
        return $false
    }
}

function Test-CommonPorts {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    
    Write-Host "`n[*] فحص المنافذ الشائعة على $IPAddress..." -ForegroundColor Yellow
    
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
        $result = Test-NetConnection -ComputerName $IPAddress -Port $port -WarningAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            $service = $commonPorts[$port]
            Write-Host "[+] المنفذ $port مفتوح - $service" -ForegroundColor Green
            $openPorts += [PSCustomObject]@{
                Port = $port
                Service = $service
                Status = "Open"
            }
        }
    }
    
    if ($openPorts.Count -eq 0) {
        Write-Host "[-] لم يتم العثور على منافذ مفتوحة" -ForegroundColor Yellow
    }
    
    return $openPorts
}

function Get-SMBShares {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    
    Write-Host "`n[*] فحص مشاركات SMB على $IPAddress..." -ForegroundColor Yellow
    
    try {
        $shares = net view \\$IPAddress 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] تم العثور على مشاركات:" -ForegroundColor Green
            Write-Host $shares
            return $shares
        } else {
            Write-Host "[-] لا يمكن الوصول إلى مشاركات SMB" -ForegroundColor Yellow
            return $null
        }
    } catch {
        Write-Host "[-] خطأ في الاتصال بـ $IPAddress" -ForegroundColor Red
        return $null
    }
}

function Export-Results {
    param (
        [Parameter(Mandatory=$true)]
        $Results
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = "network_scan_$timestamp.txt"
    
    $Results | Out-File -FilePath $outputFile -Encoding UTF8
    
    Write-Host "`n[+] تم حفظ النتائج في: $outputFile" -ForegroundColor Green
}

# البرنامج الرئيسي
function Start-NetworkScan {
    Show-Banner
    
    Write-Host "`n⚠️  تحذير: هذه الأداة للأغراض التعليمية فقط" -ForegroundColor Red
    Write-Host "تأكد من حصولك على إذن قبل فحص أي شبكة`n" -ForegroundColor Red
    
    $confirmation = Read-Host "هل تريد المتابعة؟ (Y/N)"
    if ($confirmation -ne "Y" -and $confirmation -ne "y") {
        Write-Host "تم الإلغاء" -ForegroundColor Yellow
        return
    }
    
    # جمع معلومات الجهاز المحلي
    $localInfo = Get-LocalNetworkInfo
    Write-Host "`n=== معلومات الجهاز المحلي ===" -ForegroundColor Cyan
    Write-Host "اسم الجهاز: $($localInfo.Hostname)"
    Write-Host "نظام التشغيل: $($localInfo.OS)"
    Write-Host "الإصدار: $($localInfo.OSVersion)"
    Write-Host "المعمارية: $($localInfo.Architecture)"
    Write-Host "`nعناوين IP:"
    $localInfo.IPAddresses | Format-Table -AutoSize
    
    # اكتشاف الأجهزة
    $devices = Get-NetworkDevices
    Write-Host "`n=== الأجهزة المكتشفة ===" -ForegroundColor Cyan
    Write-Host "عدد الأجهزة: $($devices.Count)"
    $devices | Format-Table -AutoSize
    
    # فحص تفصيلي (اختياري)
    $detailedScan = Read-Host "`nهل تريد إجراء فحص تفصيلي للأجهزة؟ (Y/N)"
    if ($detailedScan -eq "Y" -or $detailedScan -eq "y") {
        $targetIP = Read-Host "أدخل عنوان IP للفحص التفصيلي"
        
        if (Test-DeviceConnectivity -IPAddress $targetIP) {
            $ports = Test-CommonPorts -IPAddress $targetIP
            $shares = Get-SMBShares -IPAddress $targetIP
            
            # حفظ النتائج
            $results = @{
                LocalInfo = $localInfo
                Devices = $devices
                DetailedScan = @{
                    TargetIP = $targetIP
                    OpenPorts = $ports
                    SMBShares = $shares
                }
            }
            
            Export-Results -Results ($results | ConvertTo-Json -Depth 5)
        }
    }
    
    Write-Host "`n[✓] اكتمل الفحص!" -ForegroundColor Green
}

# تشغيل الأداة
Start-NetworkScan
