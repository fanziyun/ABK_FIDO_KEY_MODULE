package com.abk.extension.fido

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

class SyncTriggerReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val serviceIntent = Intent(context, FidoSyncService::class.java).apply {
            action = FidoSyncService.ACTION_SYNC_NOW
            putExtra(FidoSyncService.EXTRA_REASON, intent?.action ?: "broadcast")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
    }
}
