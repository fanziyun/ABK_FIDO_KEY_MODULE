package com.abk.extension.fido

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.util.Base64
import java.io.File

private const val LOCAL_DB_NAME = "abk_fido.db"
private const val METADATA_DB_PATH = "/metadata/abk_fido.db"
private const val METADATA_BLOB_PATH = "/metadata/abk_fido_store.bin"
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
            when (importDb.exitCode) {
                0 -> notes += "imported sqlite mirror from /metadata"
                RootShell.EXIT_MISSING -> notes += "metadata sqlite mirror not found"
                else -> return SyncResult(false, notes + "failed to import metadata db")
            }

            val repository = StoreSnapshotRepository(localDbFile)
            repository.ensureSchema()

            val metadataBlob = RootShell.readFileBase64(METADATA_BLOB_PATH)
            val localBlob = repository.loadSnapshot()

            when (metadataBlob.exitCode) {
                0 -> {
                    val blob = runCatching {
                        Base64.decode(metadataBlob.stdout, Base64.DEFAULT)
                    }.getOrElse {
                        return SyncResult(false, notes + "kernel blob decode failed")
                    }
                    if (localBlob == null || !blob.contentEquals(localBlob)) {
                        repository.saveSnapshot(blob)
                        notes += "captured kernel blob into sqlite"
                    } else {
                        notes += "kernel blob already mirrored"
                    }
                }
                RootShell.EXIT_MISSING -> {
                    if (localBlob != null) {
                        val exportBlob = RootShell.writeFileBase64(
                            path = METADATA_BLOB_PATH,
                            payloadBase64 = Base64.encodeToString(localBlob, Base64.NO_WRAP)
                        )
                        if (!exportBlob.success) {
                            return SyncResult(false, notes + "failed to restore kernel blob to /metadata")
                        }
                        notes += "restored kernel blob from sqlite"
                    } else {
                        notes += "kernel blob not found"
                    }
                }
                else -> return SyncResult(false, notes + "failed to read kernel blob from /metadata")
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
