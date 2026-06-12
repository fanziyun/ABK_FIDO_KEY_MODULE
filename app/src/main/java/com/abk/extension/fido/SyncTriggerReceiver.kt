package com.abk.extension.fido

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import kotlin.concurrent.thread

class SyncTriggerReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val pendingResult = goAsync()
        val action = intent?.action ?: "unknown"
        val appContext = context.applicationContext

        thread(name = "abk-fido-sync-receiver") {
            try {
                val result = MetadataSyncCoordinator(appContext).syncNow(action)
                Log.i("AbkFidoCompanion", result.userMessage(appContext))
            } finally {
                pendingResult.finish()
            }
        }
    }
}
