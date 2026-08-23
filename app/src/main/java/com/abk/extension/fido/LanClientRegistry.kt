package com.abk.extension.fido

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

internal enum class LanClientStatus {
    /** Seen once, waiting for the user to decide. Sessions are refused. */
    PENDING,
    AUTHORIZED,
    BLOCKED,
    ;

    companion object {
        fun parse(value: String?): LanClientStatus =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: PENDING
    }
}

internal class LanClientRecord(
    val id: String,
    val name: String,
    val os: String,
    val address: String,
    val status: LanClientStatus,
    val firstSeen: Long,
    val lastSeen: Long,
    val sessions: Int,
) {
    /** The name for a log line, where there is no context to translate with. */
    val logName: String get() = name.ifBlank { "unnamed" }

    /** The name to put on screen, so the fallback can be translated. */
    fun displayName(context: Context): String = when {
        name.isNotBlank() -> name
        anonymous -> context.getString(R.string.lan_client_at_address, address)
        else -> context.getString(R.string.lan_client_unnamed)
    }

    /** True for a client that could not name itself, i.e. an older agent. */
    val anonymous: Boolean get() = id.startsWith(ADDRESS_ID_PREFIX)

    companion object {
        const val ADDRESS_ID_PREFIX = "addr:"
    }
}

/**
 * The list of desktops allowed to use the key over the LAN.
 *
 * The pairing code only protects the transport: anyone who learns it can open a
 * session. This registry adds the second half of that decision — a desktop
 * announces a stable id in its hello frame, lands here as [LanClientStatus.PENDING],
 * and stays refused until the user authorizes it in the app.
 */
internal class LanClientRegistry private constructor(private val prefs: SharedPreferences) {

    fun list(): List<LanClientRecord> = synchronized(lock) { load() }
        .sortedWith(
            compareByDescending<LanClientRecord> { it.status == LanClientStatus.PENDING }
                .thenByDescending { it.lastSeen }
        )

    fun pendingCount(): Int = synchronized(lock) { load().count { it.status == LanClientStatus.PENDING } }

    fun authorizedCount(): Int = synchronized(lock) { load().count { it.status == LanClientStatus.AUTHORIZED } }

    /**
     * Record a connection attempt and report the decision that applies to it.
     * A brand new client is authorized straight away only when the user asked
     * for that with [FidoSettings.autoAuthorizeNewClients].
     */
    fun onHello(
        id: String,
        name: String,
        os: String,
        address: String,
        autoAuthorize: Boolean,
    ): LanClientRecord = synchronized(lock) {
        val now = System.currentTimeMillis()
        val records = load().toMutableList()
        val index = records.indexOfFirst { it.id == id }
        val existing = records.getOrNull(index)
        val updated = LanClientRecord(
            id = id,
            name = name.ifBlank { existing?.name.orEmpty() },
            os = os.ifBlank { existing?.os.orEmpty() },
            address = address,
            status = existing?.status
                ?: if (autoAuthorize) LanClientStatus.AUTHORIZED else LanClientStatus.PENDING,
            firstSeen = existing?.firstSeen ?: now,
            lastSeen = now,
            sessions = (existing?.sessions ?: 0) + 1,
        )
        if (index >= 0) records[index] = updated else records += updated
        save(records)
        updated
    }

    fun setStatus(id: String, status: LanClientStatus) = synchronized(lock) {
        val records = load().toMutableList()
        val index = records.indexOfFirst { it.id == id }
        if (index < 0) return@synchronized
        val existing = records[index]
        records[index] = LanClientRecord(
            id = existing.id,
            name = existing.name,
            os = existing.os,
            address = existing.address,
            status = status,
            firstSeen = existing.firstSeen,
            lastSeen = existing.lastSeen,
            sessions = existing.sessions,
        )
        save(records)
    }

    fun remove(id: String) = synchronized(lock) {
        save(load().filterNot { it.id == id })
    }

    private fun load(): List<LanClientRecord> {
        val raw = prefs.getString(KEY_CLIENTS, null) ?: return emptyList()
        val array = runCatching { JSONArray(raw) }.getOrNull() ?: return emptyList()
        val out = ArrayList<LanClientRecord>(array.length())
        for (i in 0 until array.length()) {
            val entry = array.optJSONObject(i) ?: continue
            val id = entry.optString("id")
            if (id.isBlank()) continue
            out += LanClientRecord(
                id = id,
                name = entry.optString("name"),
                os = entry.optString("os"),
                address = entry.optString("address"),
                status = LanClientStatus.parse(entry.optString("status")),
                firstSeen = entry.optLong("first_seen"),
                lastSeen = entry.optLong("last_seen"),
                sessions = entry.optInt("sessions"),
            )
        }
        return out
    }

    private fun save(records: List<LanClientRecord>) {
        val array = JSONArray()
        records.take(MAX_RECORDS).forEach { record ->
            array.put(
                JSONObject()
                    .put("id", record.id)
                    .put("name", record.name)
                    .put("os", record.os)
                    .put("address", record.address)
                    .put("status", record.status.name)
                    .put("first_seen", record.firstSeen)
                    .put("last_seen", record.lastSeen)
                    .put("sessions", record.sessions)
            )
        }
        prefs.edit().putString(KEY_CLIENTS, array.toString()).apply()
    }

    companion object {
        private const val PREFS_NAME = "abk_fido_lan_clients"
        private const val KEY_CLIENTS = "clients"
        private const val MAX_RECORDS = 64
        private val lock = Any()

        fun of(context: Context): LanClientRegistry {
            val deviceContext = context.applicationContext.createDeviceProtectedStorageContext()
            return LanClientRegistry(deviceContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE))
        }

        /**
         * Clamp a name a desktop sent us. It is untrusted network input that
         * ends up in a list row, so anything that could break the layout or a
         * log line is dropped.
         */
        fun sanitizeLabel(value: String?, maxLength: Int = 48): String {
            if (value.isNullOrEmpty()) return ""
            return value.asSequence()
                .filter { it.code >= 0x20 && it.code != 0x7f }
                .take(maxLength)
                .joinToString("")
                .trim()
        }

        /** Accept only a self-assigned hex id, so one client cannot impersonate another's format. */
        fun sanitizeId(value: String?): String? {
            val trimmed = value?.trim()?.lowercase().orEmpty()
            if (!trimmed.matches(Regex("[0-9a-f]{16,64}"))) return null
            return trimmed
        }
    }
}
