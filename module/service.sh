#!/system/bin/sh
# CLARA Security - Boot Service Script v2.0
# Bu script boot tamamlandığında çalışır

MODDIR=${0%/*}
CLARA_DATA="/data/clara"
LOG_FILE="$CLARA_DATA/logs/boot.log"

# Log fonksiyonu
log() {
    echo "[CLARA] $(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

# Hata log fonksiyonu
log_error() {
    echo "[CLARA] $(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE"
}

# =============================================================================
# Klasör Yapısı Oluştur
# =============================================================================
mkdir -p "$CLARA_DATA/logs"
mkdir -p "$CLARA_DATA/quarantine"
mkdir -p "$CLARA_DATA/cache"
mkdir -p "$CLARA_DATA/database"
mkdir -p "$CLARA_DATA/config"

# İzinler
chmod 755 "$CLARA_DATA"
chmod 755 "$CLARA_DATA/logs"
chmod 700 "$CLARA_DATA/quarantine"
chmod 755 "$CLARA_DATA/cache"
chmod 755 "$CLARA_DATA/database"
chmod 700 "$CLARA_DATA/config"

log "CLARA Security v0.2.0 başlatılıyor..."
log "Modül dizini: $MODDIR"

# =============================================================================
# Konfigürasyon Kopyala
# =============================================================================
if [ -f "$MODDIR/system/etc/clara/config.json" ]; then
    cp "$MODDIR/system/etc/clara/config.json" "$CLARA_DATA/config/" 2>/dev/null
    log "Konfigürasyon kopyalandı"
fi

# =============================================================================
# Model Cache
# =============================================================================
if [ -d "$MODDIR/system/etc/clara/models" ]; then
    cp -r "$MODDIR/system/etc/clara/models"/* "$CLARA_DATA/cache/" 2>/dev/null
    log "AI modelleri cache'e kopyalandı"
fi

# =============================================================================
# Binary İzinleri
# =============================================================================
BINARIES="clara_orchestrator clara_security_core clara_privacy_core clara_app_manager clara_cli"

for binary in $BINARIES; do
    if [ -f "$MODDIR/system/bin/$binary" ]; then
        chmod 755 "$MODDIR/system/bin/$binary"
    fi
done

# =============================================================================
# Orchestrator Başlat
# =============================================================================
start_orchestrator() {
    if pgrep -x "clara_orchestrator" > /dev/null; then
        log "Orchestrator zaten çalışıyor"
        return 0
    fi
    
    if [ -f "$MODDIR/system/bin/clara_orchestrator" ]; then
        nohup "$MODDIR/system/bin/clara_orchestrator" >> "$CLARA_DATA/logs/orchestrator.log" 2>&1 &
        ORCH_PID=$!
        echo $ORCH_PID > "$CLARA_DATA/orchestrator.pid"
        log "Orchestrator başlatıldı (PID: $ORCH_PID)"
        return 0
    else
        log_error "Orchestrator binary bulunamadı!"
        return 1
    fi
}

# =============================================================================
# Standalone Daemon'ları Başlat (Orchestrator yoksa fallback)
# =============================================================================
start_standalone() {
    log "Standalone mod başlatılıyor..."
    
    # Security Core
    if [ -f "$MODDIR/system/bin/clara_security_core" ]; then
        if ! pgrep -x "clara_security_core" > /dev/null; then
            nohup "$MODDIR/system/bin/clara_security_core" >> "$CLARA_DATA/logs/security_core.log" 2>&1 &
            log "Security Core başlatıldı (PID: $!)"
        fi
    fi
    
    # Privacy Core
    if [ -f "$MODDIR/system/bin/clara_privacy_core" ]; then
        if ! pgrep -x "clara_privacy_core" > /dev/null; then
            nohup "$MODDIR/system/bin/clara_privacy_core" >> "$CLARA_DATA/logs/privacy_core.log" 2>&1 &
            log "Privacy Core başlatıldı (PID: $!)"
        fi
    fi
    
    # App Manager
    if [ -f "$MODDIR/system/bin/clara_app_manager" ]; then
        if ! pgrep -x "clara_app_manager" > /dev/null; then
            nohup "$MODDIR/system/bin/clara_app_manager" >> "$CLARA_DATA/logs/app_manager.log" 2>&1 &
            log "App Manager başlatıldı (PID: $!)"
        fi
    fi
}

# =============================================================================
# Ana Başlatma
# =============================================================================

# Boot tamamlanana kadar bekle
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done

# Biraz daha bekle (sistem stabilize olsun)
sleep 10

log "Boot tamamlandı, servisler başlatılıyor..."

# Önce orchestrator'ı dene
if start_orchestrator; then
    # Orchestrator'ın servisleri başlatmasını bekle
    sleep 5
    
    # Kontrol et
    if pgrep -x "clara_orchestrator" > /dev/null; then
        log "Orchestrator modunda çalışıyor"
    else
        log_error "Orchestrator başarısız, standalone moda geçiliyor"
        start_standalone
    fi
else
    start_standalone
fi

# =============================================================================
# Durum Raporu
# =============================================================================
sleep 2

RUNNING_COUNT=$(pgrep -c "clara_" 2>/dev/null || echo "0")
log "Başlatma tamamlandı: $RUNNING_COUNT servis çalışıyor"

# Çalışan servisleri logla
for proc in clara_orchestrator clara_security_core clara_privacy_core clara_app_manager; do
    if pgrep -x "$proc" > /dev/null; then
        PID=$(pgrep -x "$proc")
        log "  ✓ $proc (PID: $PID)"
    else
        log "  ✗ $proc (çalışmıyor)"
    fi
done

log "CLARA Security hazır"
