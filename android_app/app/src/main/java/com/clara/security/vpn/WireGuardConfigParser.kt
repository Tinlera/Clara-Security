package com.clara.security.vpn

import android.content.Context
import android.net.Uri
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * WireGuard config dosyası (.conf) parser
 * 
 * Örnek Mullvad config:
 * ```
 * [Interface]
 * PrivateKey = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=
 * Address = 10.66.123.45/32,fc00:bbbb:bbbb:bb01::1:2345/128
 * DNS = 10.64.0.1
 * 
 * [Peer]
 * PublicKey = yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy=
 * AllowedIPs = 0.0.0.0/0,::0/0
 * Endpoint = se-sto-wg-001.relays.mullvad.net:51820
 * ```
 */
data class WireGuardConfigFile(
    // Interface section
    val privateKey: String,
    val address: List<String>,
    val dns: List<String>,
    val mtu: Int? = null,
    
    // Peer section
    val publicKey: String,
    val allowedIPs: List<String>,
    val endpoint: String,
    val persistentKeepalive: Int? = null,
    val presharedKey: String? = null,
    
    // Meta
    val name: String = "Unknown",
    val rawConfig: String = ""
)

object WireGuardConfigParser {
    
    /**
     * Config dosyasını parse eder
     */
    fun parse(content: String, name: String = "Imported Config"): WireGuardConfigFile? {
        try {
            val lines = content.lines()
            
            var currentSection = ""
            
            // Interface values
            var privateKey = ""
            var address = mutableListOf<String>()
            var dns = mutableListOf<String>()
            var mtu: Int? = null
            
            // Peer values
            var publicKey = ""
            var allowedIPs = mutableListOf<String>()
            var endpoint = ""
            var persistentKeepalive: Int? = null
            var presharedKey: String? = null
            
            for (line in lines) {
                val trimmed = line.trim()
                
                // Skip empty lines and comments
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
                
                // Section header
                if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                    currentSection = trimmed.removeSurrounding("[", "]").lowercase()
                    continue
                }
                
                // Key-value pair
                val parts = trimmed.split("=", limit = 2)
                if (parts.size != 2) continue
                
                val key = parts[0].trim().lowercase()
                val value = parts[1].trim()
                
                when (currentSection) {
                    "interface" -> {
                        when (key) {
                            "privatekey" -> privateKey = value
                            "address" -> address.addAll(value.split(",").map { it.trim() })
                            "dns" -> dns.addAll(value.split(",").map { it.trim() })
                            "mtu" -> mtu = value.toIntOrNull()
                        }
                    }
                    "peer" -> {
                        when (key) {
                            "publickey" -> publicKey = value
                            "allowedips" -> allowedIPs.addAll(value.split(",").map { it.trim() })
                            "endpoint" -> endpoint = value
                            "persistentkeepalive" -> persistentKeepalive = value.toIntOrNull()
                            "presharedkey" -> presharedKey = value
                        }
                    }
                }
            }
            
            // Validate required fields
            if (privateKey.isEmpty() || publicKey.isEmpty() || endpoint.isEmpty()) {
                return null
            }
            
            return WireGuardConfigFile(
                privateKey = privateKey,
                address = address,
                dns = dns,
                mtu = mtu,
                publicKey = publicKey,
                allowedIPs = allowedIPs.ifEmpty { listOf("0.0.0.0/0", "::/0") },
                endpoint = endpoint,
                persistentKeepalive = persistentKeepalive ?: 25,
                presharedKey = presharedKey,
                name = name,
                rawConfig = content
            )
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
    
    /**
     * URI'den config dosyasını oku ve parse et
     */
    fun parseFromUri(context: Context, uri: Uri): WireGuardConfigFile? {
        return try {
            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                val reader = BufferedReader(InputStreamReader(inputStream))
                val content = reader.readText()
                
                // Dosya adından config adı çıkar
                val fileName = uri.lastPathSegment ?: "config"
                val configName = extractConfigName(fileName, content)
                
                parse(content, configName)
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
    
    /**
     * Dosya adından veya içerikten config adı çıkar
     */
    private fun extractConfigName(fileName: String, content: String): String {
        // Dosya adından .conf uzantısını kaldır
        val baseName = fileName.removeSuffix(".conf")
        
        // Mullvad formatı: mullvad-se1.conf -> Sweden
        val mullvadRegex = Regex("mullvad-([a-z]{2})(\\d+)?")
        val match = mullvadRegex.find(baseName.lowercase())
        
        if (match != null) {
            val countryCode = match.groupValues[1]
            val serverNum = match.groupValues.getOrNull(2) ?: ""
            val countryName = getCountryName(countryCode)
            return "Mullvad - $countryName $serverNum".trim()
        }
        
        // Endpoint'ten çıkar
        val endpointRegex = Regex("([a-z]{2})-[a-z]+-wg-\\d+")
        val endpointMatch = endpointRegex.find(content)
        if (endpointMatch != null) {
            val countryCode = endpointMatch.groupValues[1]
            val countryName = getCountryName(countryCode)
            return "Mullvad - $countryName"
        }
        
        return baseName.ifEmpty { "Imported Config" }
    }
    
    /**
     * Ülke kodundan ülke adı
     */
    private fun getCountryName(code: String): String {
        return when (code.lowercase()) {
            "se" -> "Sweden"
            "de" -> "Germany"
            "nl" -> "Netherlands"
            "us" -> "USA"
            "gb", "uk" -> "UK"
            "ch" -> "Switzerland"
            "jp" -> "Japan"
            "sg" -> "Singapore"
            "au" -> "Australia"
            "ca" -> "Canada"
            "fr" -> "France"
            "it" -> "Italy"
            "es" -> "Spain"
            "no" -> "Norway"
            "fi" -> "Finland"
            "dk" -> "Denmark"
            "at" -> "Austria"
            "be" -> "Belgium"
            "pl" -> "Poland"
            "cz" -> "Czech Republic"
            "ro" -> "Romania"
            "bg" -> "Bulgaria"
            "hu" -> "Hungary"
            "ie" -> "Ireland"
            "pt" -> "Portugal"
            "lu" -> "Luxembourg"
            "hk" -> "Hong Kong"
            "br" -> "Brazil"
            "tr" -> "Turkey"
            else -> code.uppercase()
        }
    }
    
    /**
     * Config'i tekrar .conf formatına dönüştür
     */
    fun toConfigString(config: WireGuardConfigFile): String {
        return buildString {
            appendLine("[Interface]")
            appendLine("PrivateKey = ${config.privateKey}")
            appendLine("Address = ${config.address.joinToString(",")}")
            if (config.dns.isNotEmpty()) {
                appendLine("DNS = ${config.dns.joinToString(",")}")
            }
            config.mtu?.let { appendLine("MTU = $it") }
            appendLine()
            appendLine("[Peer]")
            appendLine("PublicKey = ${config.publicKey}")
            appendLine("AllowedIPs = ${config.allowedIPs.joinToString(",")}")
            appendLine("Endpoint = ${config.endpoint}")
            config.persistentKeepalive?.let { appendLine("PersistentKeepalive = $it") }
            config.presharedKey?.let { appendLine("PresharedKey = $it") }
        }
    }
}
