package com.abk.extension.fido

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.util.Log

class FidoInitProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        Log.i(TAG, "provider init")
        context?.let(::startSyncService)
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?
    ): Int = 0

    private fun startSyncService(context: Context) {
        val intent = Intent(context, FidoSyncService::class.java).apply {
            action = FidoSyncService.ACTION_SYNC_NOW
            putExtra(FidoSyncService.EXTRA_REASON, "provider_init")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    companion object {
        private const val TAG = "AbkFidoCompanion"
    }
}
