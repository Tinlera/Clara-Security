#!/bin/bash
# CLARA Security Module Packager v2
# Tüm daemon'ları KernelSU modülü olarak paketler

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║         CLARA Security Module Packager v2.0              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DAEMON_DIR="$PROJECT_DIR/daemon"
BUILD_DIR="$DAEMON_DIR/build_arm64-v8a"
MODULE_DIR="$PROJECT_DIR/module"
OUTPUT_DIR="$PROJECT_DIR/output"

mkdir -p "$OUTPUT_DIR"

# Versiyon bilgisi
VERSION=$(grep "version=" "$MODULE_DIR/module.prop" | cut -d'=' -f2)
VERSION_CODE=$(grep "versionCode=" "$MODULE_DIR/module.prop" | cut -d'=' -f2)
echo -e "${GREEN}Versiyon:${NC} $VERSION (kod: $VERSION_CODE)"

# Build kontrolü
if [ ! -f "$BUILD_DIR/clara_orchestrator" ]; then
    echo -e "${YELLOW}Binary'ler bulunamadı, önce derleniyor...${NC}"
    "$SCRIPT_DIR/build_android.sh"
fi

# Geçici dizin
TEMP_DIR=$(mktemp -d)
MODULE_TEMP="$TEMP_DIR/clara_security"
mkdir -p "$MODULE_TEMP"

echo -e "${YELLOW}[1/6] Modül dosyaları kopyalanıyor...${NC}"

# Ana modül dosyaları
cp "$MODULE_DIR/module.prop" "$MODULE_TEMP/"
cp "$MODULE_DIR/service.sh" "$MODULE_TEMP/"
cp "$MODULE_DIR/post-fs-data.sh" "$MODULE_TEMP/"
cp "$MODULE_DIR/sepolicy.rule" "$MODULE_TEMP/"

# Dizin yapısı
echo -e "${YELLOW}[2/6] Sistem dizinleri oluşturuluyor...${NC}"

mkdir -p "$MODULE_TEMP/system/bin"
mkdir -p "$MODULE_TEMP/system/lib64"
mkdir -p "$MODULE_TEMP/system/etc/clara/models"
mkdir -p "$MODULE_TEMP/system/etc/clara/rules"
mkdir -p "$MODULE_TEMP/system/etc/clara/locale"

# Binary'leri kopyala
echo -e "${YELLOW}[3/6] Binary'ler kopyalanıyor...${NC}"

BINARIES=(
    "clara_orchestrator"
    "clara_security_core"
    "clara_privacy_core"
    "clara_app_manager"
    "clara_cli"
)

for binary in "${BINARIES[@]}"; do
    if [ -f "$BUILD_DIR/$binary" ]; then
        cp "$BUILD_DIR/$binary" "$MODULE_TEMP/system/bin/"
        chmod 755 "$MODULE_TEMP/system/bin/$binary"
        echo -e "  ${GREEN}✓${NC} $binary"
    else
        echo -e "  ${YELLOW}!${NC} $binary (placeholder oluşturuluyor)"
        touch "$MODULE_TEMP/system/bin/$binary"
    fi
done

# C++ shared library (NDK'dan)
if [ -n "$ANDROID_NDK" ]; then
    LIBCPP="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so"
    if [ -f "$LIBCPP" ]; then
        cp "$LIBCPP" "$MODULE_TEMP/system/lib64/"
        echo -e "  ${GREEN}✓${NC} libc++_shared.so"
    fi
fi

# Konfigürasyon
echo -e "${YELLOW}[4/6] Konfigürasyon dosyaları oluşturuluyor...${NC}"

cp "$DAEMON_DIR/config.json" "$MODULE_TEMP/system/etc/clara/"

# Tracker blocklist (placeholder)
cat > "$MODULE_TEMP/system/etc/clara/rules/blocklist.txt" << 'EOF'
# CLARA Security - Tracker Blocklist
# Bu dosya otomatik güncellenir
# Format: domain per line

# Bilinen tracker'lar
analytics.google.com
googleadservices.com
doubleclick.net
facebook.net
graph.facebook.com
pixel.facebook.com
EOF

# Malware hash DB
cat > "$MODULE_TEMP/system/etc/clara/rules/malware_hashes.txt" << 'EOF'
# CLARA Security - Known Malware Hashes
# Format: SHA256 hash (one per line)
# Bu dosya otomatik güncellenir
EOF

# Whitelist
cat > "$MODULE_TEMP/system/etc/clara/rules/whitelist.json" << 'EOF'
{
    "trusted_senders": [
        "+90850",
        "BANKA",
        "PTT",
        "TURKCELL",
        "VODAFONE",
        "TURK TELEKOM"
    ],
    "trusted_apps": [
        "com.google.android.gms",
        "com.android.vending",
        "com.whatsapp",
        "org.telegram.messenger"
    ]
}
EOF

# Dil dosyaları
echo -e "${YELLOW}[5/6] Dil dosyaları oluşturuluyor...${NC}"

cat > "$MODULE_TEMP/system/etc/clara/locale/tr.json" << 'EOF'
{
    "app_name": "CLARA Güvenlik",
    "threat_detected": "Tehdit Tespit Edildi",
    "sms_phishing": "Phishing SMS engellendi",
    "file_malware": "Zararlı dosya bulundu",
    "network_anomaly": "Şüpheli ağ aktivitesi",
    "app_suspicious": "Şüpheli uygulama davranışı",
    "keylogger_warning": "Keylogger şüphesi",
    "quarantined": "Karantinaya alındı",
    "blocked": "Engellendi",
    "safe": "Güvenli",
    "scanning": "Taranıyor...",
    "protection_active": "Koruma aktif",
    "last_scan": "Son tarama",
    "threats_blocked": "Engellenen tehdit",
    "trackers_blocked": "Engellenen tracker",
    "root_hidden": "Root gizlendi"
}
EOF

cat > "$MODULE_TEMP/system/etc/clara/locale/en.json" << 'EOF'
{
    "app_name": "CLARA Security",
    "threat_detected": "Threat Detected",
    "sms_phishing": "Phishing SMS blocked",
    "file_malware": "Malware file found",
    "network_anomaly": "Suspicious network activity",
    "app_suspicious": "Suspicious app behavior",
    "keylogger_warning": "Keylogger suspected",
    "quarantined": "Quarantined",
    "blocked": "Blocked",
    "safe": "Safe",
    "scanning": "Scanning...",
    "protection_active": "Protection active",
    "last_scan": "Last scan",
    "threats_blocked": "Threats blocked",
    "trackers_blocked": "Trackers blocked",
    "root_hidden": "Root hidden"
}
EOF

# AI Model placeholder'ları
touch "$MODULE_TEMP/system/etc/clara/models/sms_phishing.tflite"
touch "$MODULE_TEMP/system/etc/clara/models/malware_classifier.tflite"
touch "$MODULE_TEMP/system/etc/clara/models/network_anomaly.tflite"

# ZIP olarak paketle
echo -e "${YELLOW}[6/6] Modül paketleniyor...${NC}"

OUTPUT_FILE="$OUTPUT_DIR/CLARA_Security_${VERSION}.zip"

cd "$MODULE_TEMP"
zip -r "$OUTPUT_FILE" ./* -x "*.DS_Store"

# Temizlik
rm -rf "$TEMP_DIR"

# Sonuç
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Paketleme Başarıyla Tamamlandı!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Çıktı:${NC} $OUTPUT_FILE"
echo ""

# Modül içeriği
echo "Modül İçeriği:"
unzip -l "$OUTPUT_FILE" | tail -n +4 | head -n -2 | awk '{print "  " $4}'

echo ""
echo -e "${YELLOW}Kurulum:${NC}"
echo "  1. ZIP dosyasını telefona kopyala"
echo "  2. KernelSU Manager → Modüller → Depodan yükle"
echo "  3. ZIP dosyasını seç"
echo "  4. Telefonu yeniden başlat"
