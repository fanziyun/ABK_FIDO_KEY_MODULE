package com.abk.extension.fido

import java.util.zip.CRC32

/**
 * Reader/writer for the driver's persisted store, `/metadata/abk_fido_store.bin`.
 *
 * The layout is `struct abk_fido_store_disk` from
 * files/drivers/abk_fido_key/core.c: an 84-byte header followed by 32 fixed
 * 452-byte credential slots, all little-endian. The driver reads exactly
 * [SIZE] bytes and rejects anything whose CRC32 does not cover
 * `sign_count`..end, so every edit here has to reseal the blob.
 */
internal class FidoStoreBlob private constructor(private val raw: ByteArray) {

    val signCount: Int get() = raw.readIntLe(OFF_SIGN_COUNT)
    val pinSet: Boolean get() = raw[OFF_PIN_SET].toInt() != 0

    /** The occupied slots, in slot order. */
    fun credentials(): List<FidoCredentialRecord> =
        (0 until MAX_CREDS).mapNotNull { slot -> credentialAt(slot) }

    fun freeSlots(): Int = (0 until MAX_CREDS).count { raw[slotOffset(it)].toInt() != 1 }

    fun credentialAt(slot: Int): FidoCredentialRecord? {
        val base = slotOffset(slot)
        if (raw[base].toInt() != 1) return null
        return FidoCredentialRecord(
            slot = slot,
            resident = raw[base + 1].toInt() != 0,
            userIdLen = raw[base + 2].toInt() and 0xff,
            credId = raw.copyOfRange(base + OFF_CRED_ID, base + OFF_CRED_ID + LEN_CRED_ID),
            userId = raw.copyOfRange(base + OFF_USER_ID, base + OFF_USER_ID + LEN_USER_ID),
            rpId = raw.readCString(base + OFF_RP_ID, LEN_RP_ID),
            userName = raw.readCString(base + OFF_USER_NAME, LEN_NAME),
            userDisplay = raw.readCString(base + OFF_USER_DISPLAY, LEN_NAME),
            privKey = raw.copyOfRange(base + OFF_PRIV_KEY, base + OFF_PRIV_KEY + LEN_PRIV_KEY),
            pubKey = raw.copyOfRange(base + OFF_PUB_KEY, base + OFF_PUB_KEY + LEN_PUB_KEY),
        )
    }

    /** Wipe one slot, private key included. */
    fun withoutSlot(slot: Int): FidoStoreBlob {
        val copy = raw.copyOf()
        java.util.Arrays.fill(copy, slotOffset(slot), slotOffset(slot) + CRED_SIZE, 0)
        return FidoStoreBlob(copy)
    }

    fun withRenamedSlot(slot: Int, userName: String, userDisplay: String): FidoStoreBlob {
        val copy = raw.copyOf()
        val base = slotOffset(slot)
        copy.writeCString(base + OFF_USER_NAME, LEN_NAME, userName)
        copy.writeCString(base + OFF_USER_DISPLAY, LEN_NAME, userDisplay)
        return FidoStoreBlob(copy)
    }

    /**
     * Place [record] in the first free slot. Returns null when the store is
     * full; the driver has no room past [MAX_CREDS].
     */
    fun withCredential(record: FidoCredentialRecord): FidoStoreBlob? {
        val slot = (0 until MAX_CREDS).firstOrNull { raw[slotOffset(it)].toInt() != 1 } ?: return null
        val copy = raw.copyOf()
        val base = slotOffset(slot)
        java.util.Arrays.fill(copy, base, base + CRED_SIZE, 0)
        copy[base] = 1
        copy[base + 1] = if (record.resident) 1 else 0
        copy[base + 2] = record.userIdLen.coerceIn(0, LEN_USER_ID).toByte()
        record.credId.copyInto(copy, base + OFF_CRED_ID, 0, minOf(record.credId.size, LEN_CRED_ID))
        record.userId.copyInto(copy, base + OFF_USER_ID, 0, minOf(record.userId.size, LEN_USER_ID))
        copy.writeCString(base + OFF_RP_ID, LEN_RP_ID, record.rpId)
        copy.writeCString(base + OFF_USER_NAME, LEN_NAME, record.userName)
        copy.writeCString(base + OFF_USER_DISPLAY, LEN_NAME, record.userDisplay)
        record.privKey.copyInto(copy, base + OFF_PRIV_KEY, 0, minOf(record.privKey.size, LEN_PRIV_KEY))
        record.pubKey.copyInto(copy, base + OFF_PUB_KEY, 0, minOf(record.pubKey.size, LEN_PUB_KEY))
        return FidoStoreBlob(copy)
    }

    /** The blob as the driver expects it, with a fresh CRC32. */
    fun toBytes(): ByteArray {
        val out = raw.copyOf()
        out.writeIntLe(OFF_MAGIC, MAGIC)
        out.writeIntLe(OFF_VERSION, VERSION)
        val crc = CRC32()
        crc.update(out, OFF_SIGN_COUNT, SIZE - OFF_SIGN_COUNT)
        out.writeIntLe(OFF_CRC32, crc.value.toInt())
        return out
    }

    companion object {
        const val SIZE = 14548
        const val HEADER_SIZE = 84
        const val CRED_SIZE = 452
        const val MAX_CREDS = 32

        private const val MAGIC = 0x41424646
        private const val VERSION = 1

        private const val OFF_MAGIC = 0
        private const val OFF_VERSION = 4
        private const val OFF_CRC32 = 8
        private const val OFF_SIGN_COUNT = 12
        private const val OFF_PIN_SET = 32

        private const val OFF_CRED_ID = 4
        private const val OFF_USER_ID = 36
        private const val OFF_RP_ID = 100
        private const val OFF_USER_NAME = 228
        private const val OFF_USER_DISPLAY = 292
        private const val OFF_PRIV_KEY = 356
        private const val OFF_PUB_KEY = 388

        private const val LEN_CRED_ID = 32
        private const val LEN_USER_ID = 64
        private const val LEN_RP_ID = 128
        private const val LEN_NAME = 64
        private const val LEN_PRIV_KEY = 32
        private const val LEN_PUB_KEY = 64

        /**
         * Accept a blob read from disk. A short file is padded and a long one
         * truncated, because the driver only ever looks at the first [SIZE]
         * bytes; a wrong magic or version is refused outright, and so is a bad
         * CRC unless [ignoreCrc] is set.
         */
        fun parse(bytes: ByteArray, ignoreCrc: Boolean = false): FidoStoreBlob? {
            if (bytes.size < HEADER_SIZE) return null
            val normalized = if (bytes.size == SIZE) bytes.copyOf() else ByteArray(SIZE).also {
                bytes.copyInto(it, 0, 0, minOf(bytes.size, SIZE))
            }
            if (normalized.readIntLe(OFF_MAGIC) != MAGIC) return null
            if (normalized.readIntLe(OFF_VERSION) != VERSION) return null
            if (!ignoreCrc && bytes.size >= SIZE) {
                val crc = CRC32()
                crc.update(normalized, OFF_SIGN_COUNT, SIZE - OFF_SIGN_COUNT)
                if (crc.value.toInt() != normalized.readIntLe(OFF_CRC32)) return null
            }
            return FidoStoreBlob(normalized)
        }

        /** An empty, valid store, used when the persisted file is missing. */
        fun empty(): FidoStoreBlob {
            val bytes = ByteArray(SIZE)
            bytes.writeIntLe(OFF_MAGIC, MAGIC)
            bytes.writeIntLe(OFF_VERSION, VERSION)
            return FidoStoreBlob(bytes)
        }

        private fun slotOffset(slot: Int): Int {
            require(slot in 0 until MAX_CREDS) { "slot $slot out of range" }
            return HEADER_SIZE + slot * CRED_SIZE
        }

        private fun ByteArray.readIntLe(offset: Int): Int =
            (this[offset].toInt() and 0xff) or
                ((this[offset + 1].toInt() and 0xff) shl 8) or
                ((this[offset + 2].toInt() and 0xff) shl 16) or
                ((this[offset + 3].toInt() and 0xff) shl 24)

        private fun ByteArray.writeIntLe(offset: Int, value: Int) {
            this[offset] = (value and 0xff).toByte()
            this[offset + 1] = ((value ushr 8) and 0xff).toByte()
            this[offset + 2] = ((value ushr 16) and 0xff).toByte()
            this[offset + 3] = ((value ushr 24) and 0xff).toByte()
        }

        private fun ByteArray.readCString(offset: Int, maxLen: Int): String {
            var end = offset
            val limit = offset + maxLen
            while (end < limit && this[end].toInt() != 0) end++
            return String(this, offset, end - offset, Charsets.UTF_8)
        }

        /** Copy [value] as NUL-terminated UTF-8, truncated on a byte boundary. */
        private fun ByteArray.writeCString(offset: Int, maxLen: Int, value: String) {
            java.util.Arrays.fill(this, offset, offset + maxLen, 0)
            val encoded = value.toByteArray(Charsets.UTF_8)
            var length = minOf(encoded.size, maxLen - 1)
            // Never leave half of a multi-byte sequence behind: if the first
            // dropped byte is a continuation byte, drop its lead byte too.
            if (length < encoded.size) {
                while (length > 0 && (encoded[length].toInt() and 0xc0) == 0x80) length--
            }
            encoded.copyInto(this, offset, 0, length)
        }
    }
}

/** One credential slot of the driver's store. */
internal class FidoCredentialRecord(
    val slot: Int,
    val resident: Boolean,
    val userIdLen: Int,
    val credId: ByteArray,
    val userId: ByteArray,
    val rpId: String,
    val userName: String,
    val userDisplay: String,
    val privKey: ByteArray,
    val pubKey: ByteArray,
) {
    val credIdHex: String get() = credId.joinToString("") { "%02x".format(it) }

    /** What the key list shows as the account this credential belongs to. */
    val accountLabel: String
        get() = userDisplay.ifBlank { userName }.ifBlank { "Unnamed account" }

    val siteLabel: String get() = rpId.ifBlank { "Unknown site" }
}
