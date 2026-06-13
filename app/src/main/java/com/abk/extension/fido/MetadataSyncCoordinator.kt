package com.abk.extension.fido

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.util.Base64
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.io.File
import java.util.zip.CRC32
import kotlin.math.min

private const val LOCAL_DB_NAME = "abk_fido.db"
private const val METADATA_DB_PATH = "/metadata/abk_fido.db"
private const val METADATA_BLOB_PATH = "/metadata/abk_fido_store.bin"
private const val STORE_DISK_CRC_OFFSET = 8
private const val STORE_DISK_SIGN_COUNT_OFFSET = 12
private const val STORE_DISK_AAGUID_OFFSET = 16
private const val STORE_DISK_PIN_SET_OFFSET = 32
private const val STORE_DISK_PIN_RETRIES_OFFSET = 33
private const val STORE_DISK_PIN_HASH_OFFSET = 36
private const val STORE_DISK_PIN_TOKEN_OFFSET = 52
private const val STORE_DISK_HEADER_SIZE = 84
private const val STORE_DISK_CRED_SIZE = 452
private const val STORE_DISK_MAX_CREDS = 32
private const val STORE_DISK_CRED_ID_OFFSET = 4
private const val STORE_DISK_CRED_RP_ID_OFFSET = 100
private const val STORE_DISK_CRED_RP_ID_SIZE = 128
private val syncLock = Any()

data class SyncResult(
    val success: Boolean,
    val notes: List<String>,
) {
    fun userMessage(context: Context): String {
        val prefix = if (success) {
            context.getString(R.string.status_success_prefix)
        } else {
            context.getString(R.string.status_failure_prefix)
        }
        return prefix + notes.joinToString("; ").ifBlank { "no-op" }
    }
}

internal class MetadataSyncCoordinator(context: Context) {
    private val appContext = context.applicationContext
    private val deviceContext = appContext.createDeviceProtectedStorageContext()
    private val localDbFile = deviceContext.getDatabasePath(LOCAL_DB_NAME)
    private val ownerUid = appContext.applicationInfo.uid

    fun syncNow(reason: String): SyncResult {
        synchronized(syncLock) {
            val notes = mutableListOf("reason=$reason")

            if (!RootShell.isRootAvailable()) {
                notes += appContext.getString(R.string.status_root_missing)
                return SyncResult(success = false, notes = notes)
            }

            localDbFile.parentFile?.mkdirs()

            val importDb = RootShell.copyFileFromMetadata(METADATA_DB_PATH, localDbFile.absolutePath, ownerUid)
            if (importDb.success) {
                notes += "imported sqlite mirror from /metadata"
            } else {
                notes += "metadata sqlite mirror not found"
            }

            val repository = StoreSnapshotRepository(localDbFile)
            repository.ensureSchema()

            val kernelCredentialCount = FidoKernelBridge.readCredentialCount() ?: 0
            val kernelBlob = FidoKernelBridge.readStoreBlobBase64()
            val metadataBlob = RootShell.readFileBase64(METADATA_BLOB_PATH)
            val localBlob = repository.loadSnapshot()
            val kernelBlobBytes = if (kernelBlob.success) {
                runCatching { Base64.decode(kernelBlob.stdout, Base64.DEFAULT) }.getOrNull()
            } else {
                null
            }
            val metadataBlobBytes = if (metadataBlob.success) {
                runCatching { Base64.decode(metadataBlob.stdout, Base64.DEFAULT) }.getOrNull()
            } else {
                null
            }
            val mergedBlob = mergeStoreSnapshots(
                mergeStoreSnapshots(localBlob, metadataBlobBytes),
                if (kernelCredentialCount > 0) kernelBlobBytes else null
            )

            if (mergedBlob != null) {
                if (localBlob == null || !mergedBlob.contentEquals(localBlob)) {
                    repository.saveSnapshot(mergedBlob)
                    notes += "updated sqlite snapshot from merged blobs"
                } else {
                    notes += "sqlite snapshot already up to date"
                }

                if (kernelBlobBytes == null || !mergedBlob.contentEquals(kernelBlobBytes) ||
                    mergedBlob.storeCredentialCount() != kernelCredentialCount) {
                    val restoreKernel = FidoKernelBridge.writeStoreBlobBase64(
                        Base64.encodeToString(mergedBlob, Base64.NO_WRAP)
                    )
                    if (restoreKernel.success) {
                        notes += "restored merged blob into kernel"
                    } else {
                        notes += "kernel blob restore via sysfs failed"
                    }
                } else {
                    notes += "kernel blob already up to date"
                }

                val exportBlob = RootShell.writeFileBase64(
                    path = METADATA_BLOB_PATH,
                    payloadBase64 = Base64.encodeToString(mergedBlob, Base64.NO_WRAP)
                )
                if (!exportBlob.success) {
                    return SyncResult(false, notes + "failed to export merged blob to /metadata")
                }
                notes += "exported merged blob to /metadata"
            } else {
                notes += "kernel blob not found"
            }

            val exportDb = RootShell.copyFileToMetadata(localDbFile.absolutePath, METADATA_DB_PATH)
            if (!exportDb.success) {
                return SyncResult(false, notes + "failed to export sqlite mirror to /metadata")
            }
            notes += "exported sqlite mirror to /metadata"
            return SyncResult(true, notes)
        }
    }
}

private fun mergeStoreSnapshots(preferred: ByteArray?, fallback: ByteArray?): ByteArray? {
    val left = preferred?.let(StoreDiskSnapshot::parse)
    val right = fallback?.let(StoreDiskSnapshot::parse)
    return when {
        left == null -> fallback
        right == null -> preferred
        else -> left.merge(right).encode()
    }
}

private fun ByteArray.storeCredentialCount(): Int {
    if (size < STORE_DISK_HEADER_SIZE) return -1
    val credsBytes = size - STORE_DISK_HEADER_SIZE
    if (credsBytes <= 0) return 0
    val slots = minOf(credsBytes / STORE_DISK_CRED_SIZE, STORE_DISK_MAX_CREDS)
    var count = 0
    for (i in 0 until slots) {
        val offset = STORE_DISK_HEADER_SIZE + (i * STORE_DISK_CRED_SIZE)
        if (getOrNull(offset)?.toInt() == 1) {
            count++
        }
    }
    return count
}

private data class StoreDiskSnapshot(
    val raw: ByteArray,
    val signCount: Int,
    val aaguid: ByteArray,
    val pinSet: Byte,
    val pinRetries: Byte,
    val pinHash: ByteArray,
    val pinToken: ByteArray,
    val creds: MutableList<CredSlot>
) {
    data class CredSlot(
        val index: Int,
        val blob: ByteArray,
        val credId: ByteArray,
        val rpId: String,
        val inUse: Boolean
    )

    fun merge(other: StoreDiskSnapshot): StoreDiskSnapshot {
        val mergedCreds = linkedMapOf<String, CredSlot>()
        (creds + other.creds)
            .filter { it.inUse }
            .forEach { slot ->
                mergedCreds.putIfAbsent(slot.key(), slot)
            }

        val encoded = raw.copyOf()
        var cursor = STORE_DISK_HEADER_SIZE
        repeat(STORE_DISK_MAX_CREDS) { slotIndex ->
            val slot = mergedCreds.values.elementAtOrNull(slotIndex)
            val slotBytes = slot?.blob ?: ByteArray(STORE_DISK_CRED_SIZE)
            System.arraycopy(slotBytes, 0, encoded, cursor, min(slotBytes.size, STORE_DISK_CRED_SIZE))
            cursor += STORE_DISK_CRED_SIZE
        }

        val newer = if (other.signCount >= signCount) other else this
        return copy(
            raw = encoded,
            signCount = newer.signCount,
            aaguid = newer.aaguid,
            pinSet = newer.pinSet,
            pinRetries = newer.pinRetries,
            pinHash = newer.pinHash,
            pinToken = newer.pinToken,
            creds = mergedCreds.values.toMutableList()
        )
    }

    fun encode(): ByteArray {
        val out = raw.copyOf()
        val buffer = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(STORE_DISK_SIGN_COUNT_OFFSET, signCount)
        System.arraycopy(aaguid, 0, out, STORE_DISK_AAGUID_OFFSET, 16)
        out[STORE_DISK_PIN_SET_OFFSET] = pinSet
        out[STORE_DISK_PIN_RETRIES_OFFSET] = pinRetries
        System.arraycopy(pinHash, 0, out, STORE_DISK_PIN_HASH_OFFSET, 16)
        System.arraycopy(pinToken, 0, out, STORE_DISK_PIN_TOKEN_OFFSET, 32)
        var cursor = STORE_DISK_HEADER_SIZE
        repeat(STORE_DISK_MAX_CREDS) { slotIndex ->
            val slot = creds.elementAtOrNull(slotIndex)
            val slotBytes = slot?.blob ?: ByteArray(STORE_DISK_CRED_SIZE)
            System.arraycopy(slotBytes, 0, out, cursor, min(slotBytes.size, STORE_DISK_CRED_SIZE))
            cursor += STORE_DISK_CRED_SIZE
        }
        val crc = CRC32().apply {
            update(out, STORE_DISK_SIGN_COUNT_OFFSET, out.size - STORE_DISK_SIGN_COUNT_OFFSET)
        }.value.toInt()
        buffer.putInt(STORE_DISK_CRC_OFFSET, crc)
        return out
    }

    companion object {
        fun parse(bytes: ByteArray): StoreDiskSnapshot? {
            if (bytes.size < STORE_DISK_HEADER_SIZE) return null
            val signCount = ByteBuffer.wrap(bytes, STORE_DISK_SIGN_COUNT_OFFSET, 4).order(ByteOrder.LITTLE_ENDIAN).int
            val aaguid = bytes.copyOfRange(STORE_DISK_AAGUID_OFFSET, STORE_DISK_AAGUID_OFFSET + 16)
            val pinSet = bytes[STORE_DISK_PIN_SET_OFFSET]
            val pinRetries = bytes[STORE_DISK_PIN_RETRIES_OFFSET]
            val pinHash = bytes.copyOfRange(STORE_DISK_PIN_HASH_OFFSET, STORE_DISK_PIN_HASH_OFFSET + 16)
            val pinToken = bytes.copyOfRange(STORE_DISK_PIN_TOKEN_OFFSET, STORE_DISK_PIN_TOKEN_OFFSET + 32)
            val creds = mutableListOf<CredSlot>()
            var cursor = STORE_DISK_HEADER_SIZE
            repeat(min((bytes.size - STORE_DISK_HEADER_SIZE) / STORE_DISK_CRED_SIZE, STORE_DISK_MAX_CREDS)) { index ->
                val blob = bytes.copyOfRange(cursor, cursor + STORE_DISK_CRED_SIZE)
                val inUse = blob[0].toInt() == 1
                val credId = blob.copyOfRange(STORE_DISK_CRED_ID_OFFSET, STORE_DISK_CRED_ID_OFFSET + 32)
                val rpIdBytes = blob.copyOfRange(
                    STORE_DISK_CRED_RP_ID_OFFSET,
                    STORE_DISK_CRED_RP_ID_OFFSET + STORE_DISK_CRED_RP_ID_SIZE
                )
                val rpId = rpIdBytes.takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.UTF_8)
                creds += CredSlot(index, blob, credId, rpId, inUse)
                cursor += STORE_DISK_CRED_SIZE
            }
            return StoreDiskSnapshot(
                raw = bytes.copyOf(),
                signCount = signCount,
                aaguid = aaguid,
                pinSet = pinSet,
                pinRetries = pinRetries,
                pinHash = pinHash,
                pinToken = pinToken,
                creds = creds
            )
        }
    }
}

private fun StoreDiskSnapshot.CredSlot.key(): String =
    credId.joinToString("") { "%02x".format(it) } + "#" + rpId

private class StoreSnapshotRepository(private val dbFile: File) {
    fun ensureSchema() {
        val db = openDatabase()
        db.close()
    }

    fun loadSnapshot(): ByteArray? {
        val db = openDatabase()
        return try {
            db.rawQuery("SELECT snapshot_blob FROM store_snapshot WHERE id = 1", null).use { cursor ->
                if (cursor.moveToFirst()) cursor.getBlob(0) else null
            }
        } finally {
            db.close()
        }
    }

    fun saveSnapshot(blob: ByteArray) {
        val db = openDatabase()
        try {
            db.beginTransaction()
            db.execSQL(
                "INSERT OR REPLACE INTO store_snapshot(id, snapshot_blob, updated_at) VALUES(1, ?, ?)",
                arrayOf(blob, System.currentTimeMillis())
            )
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
            db.close()
        }
    }

    private fun openDatabase(): SQLiteDatabase {
        return try {
            openDatabaseInternal()
        } catch (_: Throwable) {
            cleanupDatabaseFiles()
            openDatabaseInternal()
        }
    }

    private fun openDatabaseInternal(): SQLiteDatabase {
        val db = SQLiteDatabase.openOrCreateDatabase(dbFile, null)
        try {
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS store_snapshot(
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    snapshot_blob BLOB NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """.trimIndent()
            )
            return db
        } catch (t: Throwable) {
            db.close()
            throw t
        }
    }

    private fun cleanupDatabaseFiles() {
        dbFile.delete()
        File(dbFile.absolutePath + "-journal").delete()
        File(dbFile.absolutePath + "-wal").delete()
        File(dbFile.absolutePath + "-shm").delete()
    }
}
