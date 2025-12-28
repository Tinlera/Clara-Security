#!/system/bin/sh
# CLARA Security - Post-FS-Data Script
# Runs before zygote starts

MODDIR=${0%/*}

# SELinux context ayarla (gerekirse)
# chcon -R u:object_r:system_file:s0 $MODDIR/system

# Binary izinlerini ayarla
chmod 755 "$MODDIR/system/bin/clara_orchestrator"
chmod 755 "$MODDIR/system/bin/clara_security_core"
chmod 755 "$MODDIR/system/bin/clara_privacy_core"
chmod 755 "$MODDIR/system/bin/clara_app_manager"
chmod 755 "$MODDIR/system/bin/clara_cli"
