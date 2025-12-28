#!/bin/bash
# CLARA Security - Android NDK ile derleme scripti v2
# Tüm daemon'ları derler

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           CLARA Security Build System v2.0               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# NDK yolu kontrolü
if [ -z "$ANDROID_NDK" ]; then
    POSSIBLE_NDK_PATHS=(
        "$HOME/Android/Sdk/ndk/26.1.10909125"
        "$HOME/Android/Sdk/ndk/25.2.9519653"
        "$HOME/Android/Sdk/ndk/27.0.11718014"
        "/opt/android-ndk"
        "$ANDROID_HOME/ndk-bundle"
    )
    
    for path in "${POSSIBLE_NDK_PATHS[@]}"; do
        if [ -d "$path" ]; then
            export ANDROID_NDK="$path"
            break
        fi
    done
fi

if [ -z "$ANDROID_NDK" ]; then
    echo -e "${RED}HATA: Android NDK bulunamadı!${NC}"
    echo "Lütfen ANDROID_NDK environment variable'ı ayarlayın:"
    echo "  export ANDROID_NDK=/path/to/ndk"
    echo ""
    echo "Veya NDK'yı yükleyin:"
    echo "  sdkmanager 'ndk;26.1.10909125'"
    exit 1
fi

echo -e "${GREEN}NDK:${NC} $ANDROID_NDK"

# Parametreler
ARCH=${1:-arm64-v8a}
API_LEVEL=${2:-30}
BUILD_TYPE=${3:-Release}

echo -e "${GREEN}Hedef Mimari:${NC} $ARCH"
echo -e "${GREEN}API Level:${NC} $API_LEVEL"
echo -e "${GREEN}Build Type:${NC} $BUILD_TYPE"
echo ""

# Proje dizini
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DAEMON_DIR="$PROJECT_DIR/daemon"
BUILD_DIR="$DAEMON_DIR/build_$ARCH"

# Build dizinini oluştur
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# CMake konfigürasyon
echo -e "${YELLOW}[1/3] CMake konfigürasyonu...${NC}"
cmake "$DAEMON_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ARCH" \
    -DANDROID_PLATFORM="android-$API_LEVEL" \
    -DANDROID_STL=c++_shared \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DANDROID_NATIVE_API_LEVEL="$API_LEVEL"

# Derleme
echo -e "${YELLOW}[2/3] Derleniyor...${NC}"
make -j$(nproc)

# Sonuç kontrolü
echo -e "${YELLOW}[3/3] Sonuç kontrolü...${NC}"

BINARIES=(
    "clara_orchestrator"
    "clara_security_core"
    "clara_privacy_core"
    "clara_app_manager"
    "clara_cli"
)

ALL_OK=true
for binary in "${BINARIES[@]}"; do
    if [ -f "$BUILD_DIR/$binary" ]; then
        SIZE=$(du -h "$BUILD_DIR/$binary" | cut -f1)
        echo -e "  ${GREEN}✓${NC} $binary ($SIZE)"
    else
        echo -e "  ${RED}✗${NC} $binary (BULUNAMADI)"
        ALL_OK=false
    fi
done

if [ "$ALL_OK" = true ]; then
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Derleme Başarıyla Tamamlandı!               ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Binary'ler: ${CYAN}$BUILD_DIR/${NC}"
    echo ""
    echo "Sonraki adım: Modül paketlemek için:"
    echo "  ./scripts/package_module.sh"
else
    echo ""
    echo -e "${RED}Bazı binary'ler derlenemedi!${NC}"
    exit 1
fi
