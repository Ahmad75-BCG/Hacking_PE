#!/bin/bash

# أداة فحص الشبكة التعليمية - للأغراض التعليمية فقط
# Network Security Scanner Tool
# المؤلف: فريق الأمن السيبراني
# الإصدار: 1.0

# الألوان
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# عرض البانر
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║          أداة فحص الشبكة التعليمية                      ║
║          Network Security Scanner Tool                   ║
║          للأغراض التعليمية فقط                          ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# جمع معلومات الجهاز المحلي
get_local_info() {
    echo -e "${YELLOW}[*] جمع معلومات الجهاز المحلي...${NC}"
    echo ""
    echo "=== معلومات الجهاز المحلي ==="
    echo "اسم الجهاز: $(hostname)"
    echo "نظام التشغيل: $(uname -s)"
    echo "إصدار النواة: $(uname -r)"
    echo "المعمارية: $(uname -m)"
    echo ""
    echo "عناوين IP:"
    
    # جمع عناوين IP (Linux)
    if command -v ip &> /dev/null; then
        ip addr show | grep -E "inet " | awk '{print "  - " $2}'
    elif command -v ifconfig &> /dev/null; then
        ifconfig | grep -E "inet " | awk '{print "  - " $2}'
    fi
}

# اكتشاف الأجهزة في الشبكة
discover_devices() {
    echo -e "${YELLOW}[*] فحص الأجهزة المتصلة بالشبكة...${NC}"
    echo ""
    
    # الحصول على subnet
    local_ip=$(ip route get 8.8.8.8 | awk '{print $7; exit}')
    subnet=$(echo $local_ip | cut -d'.' -f1-3).0/24
    
    echo "الشبكة المحلية: $subnet"
    echo ""
    echo "=== الأجهزة المكتشفة ==="
    
    # استخدام arp-scan إذا كان متاحاً
    if command -v arp-scan &> /dev/null; then
        sudo arp-scan --interface=$(ip route | grep default | awk '{print $5}') --localnet
    # أو استخدام nmap
    elif command -v nmap &> /dev/null; then
        nmap -sn $subnet | grep -E "Nmap scan report|MAC Address"
    # أو استخدام arp
    else
        echo "استخدام ARP cache:"
        arp -a
    fi
}

# اختبار الاتصال
test_connectivity() {
    local target=$1
    echo -e "${YELLOW}[*] اختبار الاتصال بـ $target...${NC}"
    
    if ping -c 2 -W 1 $target &> /dev/null; then
        echo -e "${GREEN}[+] الجهاز $target متصل${NC}"
        return 0
    else
        echo -e "${RED}[-] الجهاز $target غير متصل${NC}"
        return 1
    fi
}

# فحص المنافذ الشائعة
scan_common_ports() {
    local target=$1
    echo -e "${YELLOW}[*] فحص المنافذ الشائعة على $target...${NC}"
    echo ""
    
    # المنافذ الشائعة
    declare -A ports=(
        [22]="SSH"
        [21]="FTP"
        [80]="HTTP"
        [443]="HTTPS"
        [445]="SMB/CIFS"
        [3389]="RDP"
        [135]="RPC"
        [139]="NetBIOS"
    )
    
    for port in "${!ports[@]}"; do
        if timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null; then
            echo -e "${GREEN}[+] المنفذ $port مفتوح - ${ports[$port]}${NC}"
        fi
    done
}

# فحص مشاركات SMB
scan_smb_shares() {
    local target=$1
    echo -e "${YELLOW}[*] فحص مشاركات SMB على $target...${NC}"
    
    if command -v smbclient &> /dev/null; then
        smbclient -L //$target -N 2>/dev/null || echo -e "${RED}[-] لا يمكن الوصول إلى مشاركات SMB${NC}"
    else
        echo -e "${YELLOW}[-] smbclient غير مثبت${NC}"
    fi
}

# حفظ النتائج
save_results() {
    local output_file="network_scan_$(date +%Y%m%d_%H%M%S).txt"
    echo ""
    echo -e "${GREEN}[+] حفظ النتائج في: $output_file${NC}"
    
    {
        echo "=== تقرير فحص الشبكة ==="
        echo "التاريخ: $(date)"
        echo ""
        get_local_info
        echo ""
        discover_devices
    } > "$output_file"
}

# البرنامج الرئيسي
main() {
    show_banner
    
    echo -e "${RED}⚠️  تحذير: هذه الأداة للأغراض التعليمية فقط${NC}"
    echo -e "${RED}تأكد من حصولك على إذن قبل فحص أي شبكة${NC}"
    echo ""
    read -p "هل تريد المتابعة؟ (y/n): " confirmation
    
    if [[ ! "$confirmation" =~ ^[Yy]$ ]]; then
        echo "تم الإلغاء"
        exit 0
    fi
    
    # جمع معلومات الجهاز المحلي
    get_local_info
    echo ""
    
    # اكتشاف الأجهزة
    discover_devices
    echo ""
    
    # فحص تفصيلي (اختياري)
    read -p "هل تريد إجراء فحص تفصيلي لجهاز معين؟ (y/n): " detailed_scan
    
    if [[ "$detailed_scan" =~ ^[Yy]$ ]]; then
        read -p "أدخل عنوان IP للفحص التفصيلي: " target_ip
        echo ""
        
        if test_connectivity "$target_ip"; then
            scan_common_ports "$target_ip"
            echo ""
            scan_smb_shares "$target_ip"
        fi
        
        # حفظ النتائج
        read -p "هل تريد حفظ النتائج؟ (y/n): " save
        if [[ "$save" =~ ^[Yy]$ ]]; then
            save_results
        fi
    fi
    
    echo ""
    echo -e "${GREEN}[✓] اكتمل الفحص!${NC}"
}

# التحقق من الصلاحيات
if [ "$EUID" -ne 0 ] && command -v arp-scan &> /dev/null; then
    echo -e "${YELLOW}تحذير: بعض الميزات تتطلب صلاحيات root${NC}"
    echo "استخدم: sudo $0"
    echo ""
fi

# تشغيل البرنامج الرئيسي
main
