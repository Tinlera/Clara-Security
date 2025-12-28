package com.clara.security.model

/**
 * Tehdit bilgisi modeli
 */
data class ThreatInfo(
    val id: Long = System.currentTimeMillis(),
    val type: ThreatType = ThreatType.UNKNOWN,
    val level: ThreatLevel = ThreatLevel.LOW,
    val source: String = "",
    val description: String = "",
    val timestamp: Long = System.currentTimeMillis(),
    val confidence: Float = 0f,
    val isHandled: Boolean = false
)

enum class ThreatType {
    UNKNOWN,
    PHISHING_SMS,
    PHISHING_URL,
    MALWARE_FILE,
    SUSPICIOUS_APP,
    NETWORK_ATTACK,
    KEYLOGGER,
    ROOT_DETECTION,
    PERMISSION_ABUSE
}

enum class ThreatLevel {
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

/**
 * Daemon durumu modeli
 */
data class DaemonStatus(
    val name: String,
    val isRunning: Boolean = false,
    val pid: Int = 0,
    val lastUpdate: Long = 0,
    val threatsDetected: Int = 0,
    val eventsProcessed: Int = 0
)

/**
 * İstatistik modeli
 */
data class SecurityStats(
    val totalThreats: Int = 0,
    val threatsToday: Int = 0,
    val eventsProcessed: Int = 0,
    val appsScanned: Int = 0,
    val filesScanned: Int = 0,
    val smsScanned: Int = 0,
    val trackersBlocked: Int = 0,
    val lastScanTime: Long = 0
)

/**
 * Uygulama kilit bilgisi
 */
data class LockedApp(
    val packageName: String,
    val appName: String,
    val lockType: LockType = LockType.PIN,
    val isLocked: Boolean = true
)

enum class LockType {
    NONE,
    PIN,
    PATTERN,
    FINGERPRINT
}

/**
 * Engellenen tracker bilgisi
 */
data class BlockedTracker(
    val domain: String,
    val category: TrackerCategory,
    val blockCount: Int = 0,
    val lastBlocked: Long = 0
)

enum class TrackerCategory {
    ADVERTISING,
    ANALYTICS,
    SOCIAL,
    CRYPTOMINER,
    MALWARE,
    CUSTOM
}
