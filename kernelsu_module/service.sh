#!/system/bin/sh
# CLARA Security - Service Script (runs at boot as root)

MODDIR=${0%/*}
CLARA_DIR="/data/clara"
LOG_FILE="$CLARA_DIR/logs/service.log"

# Dizinleri oluştur
mkdir -p "$CLARA_DIR/logs"
mkdir -p "$CLARA_DIR/database"
mkdir -p "$CLARA_DIR/quarantine"
mkdir -p "$CLARA_DIR/cache"

# Log fonksiyonu
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "CLARA Security başlatılıyor..."

# Android boot tamamlanana kadar bekle
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 5
done
sleep 10

log "Boot tamamlandı, daemon'lar başlatılıyor..."

# Orchestrator daemon'ı başlat
nohup "$MODDIR/system/bin/clara_orchestrator" >> "$CLARA_DIR/logs/orchestrator.log" 2>&1 &
ORCH_PID=$!
log "Orchestrator başlatıldı (PID: $ORCH_PID)"

# Security Core daemon'ı başlat
nohup "$MODDIR/system/bin/clara_security_core" >> "$CLARA_DIR/logs/security_core.log" 2>&1 &
SEC_PID=$!
log "Security Core başlatıldı (PID: $SEC_PID)"

# Privacy Core daemon'ı başlat
nohup "$MODDIR/system/bin/clara_privacy_core" >> "$CLARA_DIR/logs/privacy_core.log" 2>&1 &
PRIV_PID=$!
log "Privacy Core başlatıldı (PID: $PRIV_PID)"

# App Manager daemon'ı başlat
nohup "$MODDIR/system/bin/clara_app_manager" >> "$CLARA_DIR/logs/app_manager.log" 2>&1 &
APP_PID=$!
log "App Manager başlatıldı (PID: $APP_PID)"

log "Tüm CLARA daemon'ları başlatıldı"
