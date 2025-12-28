#!/system/bin/sh
# CLARA Security - Uninstall Script

# Daemon'ları durdur
pkill -f clara_orchestrator
pkill -f clara_security_core
pkill -f clara_privacy_core
pkill -f clara_app_manager

# Veri dizinlerini temizle (opsiyonel - yorum satırını kaldır)
# rm -rf /data/clara
