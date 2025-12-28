#!/bin/bash
# CLARA Security - Platform Certificate Extractor
# Bu script, cihazdan platform certificate'ını çıkarır

set -e

echo "=== CLARA Platform Key Extractor ==="
echo ""

# 1. Cihazdan SystemUI.apk çek
echo "[1/4] SystemUI.apk çekiliyor..."
adb pull /system/priv-app/SystemUI/SystemUI.apk ./temp_system.apk 2>/dev/null || \
adb pull /system_ext/priv-app/SystemUI/SystemUI.apk ./temp_system.apk 2>/dev/null || \
adb pull /product/priv-app/SystemUI/SystemUI.apk ./temp_system.apk 2>/dev/null || \
{ echo "HATA: SystemUI.apk bulunamadı!"; exit 1; }

# 2. APK'dan RSA sertifikasını çıkar
echo "[2/4] Certificate çıkarılıyor..."
unzip -o temp_system.apk META-INF/*.RSA -d ./temp_cert/ 2>/dev/null || \
unzip -o temp_system.apk META-INF/*.DSA -d ./temp_cert/ 2>/dev/null

# 3. Sertifikayı PEM formatına çevir
echo "[3/4] Sertifika PEM formatına çevriliyor..."
CERT_FILE=$(find ./temp_cert/META-INF -name "*.RSA" -o -name "*.DSA" 2>/dev/null | head -1)
if [ -n "$CERT_FILE" ]; then
    openssl pkcs7 -in "$CERT_FILE" -inform DER -print_certs -out platform.x509.pem
    echo "Sertifika kaydedildi: platform.x509.pem"
fi

# 4. Temizlik
echo "[4/4] Temizlik..."
rm -rf temp_system.apk temp_cert

echo ""
echo "=== TAMAMLANDI ==="
echo ""
echo "UYARI: Bu sertifika sadece certificate'ı çıkarır."
echo "Platform KEY (.pk8) elde etmek için ROM kaynak koduna ihtiyaç var!"
echo ""
echo "Alternatif çözümler:"
echo "  1. AOSP test keys kullan (development için)"
echo "  2. KernelSU modülü olarak devam et (önerilen)"
echo "  3. Shizuku/Sui API kullan"
