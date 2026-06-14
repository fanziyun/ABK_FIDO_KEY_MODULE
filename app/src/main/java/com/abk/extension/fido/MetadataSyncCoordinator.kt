package com.abk.extension.fido

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.util.Base64
import java.io.File

private const val LOCAL_DB_NAME = "abk_fido.db"
private const val METADATA_DB_PATH = "/metadata/abk_fido.db"
private const val METADATA_BLOB_PATH = "/metadata/abk_fido_store.bin"
private const val STORE_DISK_HEADER_SIZE = 84
private const val STORE_DISK_CRED_SIZE = 452
private const val STORE_DISK_MAX_CREDS = 32
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
            val kernelBlobBytes = FidoKernelBridge.readStoreBlobBase64()
                .takeIf { it.success }
                ?.stdout
                ?.let { raw -> runCatching { Base64.decode(raw, Base64.DEFAULT) }.getOrNull() }
            val metadataBlobBytes = RootShell.readFileBase64(METADATA_BLOB_PATH)
                .takeIf { it.success }
                ?.stdout
                ?.let { raw -> runCatching { Base64.decode(raw, Base64.DEFAULT) }.getOrNull() }
            val localBlob = repository.loadSnapshot()

            if (kernelBlobBytes != null && kernelCredentialCount > 0) {
                if (localBlob == null || !kernelBlobBytes.contentEquals(localBlob)) {
                    repository.saveSnapshot(kernelBlobBytes)
                    notes += "captured kernel blob into sqlite"
                } else {
                    notes += "sqlite snapshot already matches kernel blob"
                }

                val exportBlob = RootShell.writeFileBase64(
                    path = METADATA_BLOB_PATH,
                    payloadBase64 = Base64.encodeToString(kernelBlobBytes, Base64.NO_WRAP)
                )
                if (!exportBlob.success) {
                    return SyncResult(false, notes + "failed to export kernel blob to /metadata")
                }
                notes += "exported kernel blob to /metadata"
            } else {
                val restoreBlob = metadataBlobBytes ?: localBlob
                if (restoreBlob != null) {
                    if (localBlob == null || !restoreBlob.contentEquals(localBlob)) {
                        repository.saveSnapshot(restoreBlob)
                        notes += "updated sqlite snapshot from restore blob"
                    } else {
                        notes += "sqlite snapshot already up to date"
                    }

                    val targetCount = restoreBlob.storeCredentialCount()
                    val restoreKernel = FidoKernelBridge.writeStoreBlobBase64(
                        Base64.encodeToString(restoreBlob, Base64.NO_WRAP)
                    )
                    if (restoreKernel.success) {
                        val restoredCount = FidoKernelBridge.waitForCredentialCountAtLeast(targetCount)
                        notes += "restored blob into kernel(count=${restoredCount ?: -1}/$targetCount)"
                    } else {
                        return SyncResult(false, notes + "kernel blob restore via sysfs failed")
                    }

                    val exportBlob = RootShell.writeFileBase64(
                        path = METADATA_BLOB_PATH,
                        payloadBase64 = Base64.encodeToString(restoreBlob, Base64.NO_WRAP)
                    )
                    if (!exportBlob.success) {
                        return SyncResult(false, notes + "failed to export restore blob to /metadata")
                    }
                    notes += "exported restore blob to /metadata"
                } else {
                    notes += "no stored blob available"
                }
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
