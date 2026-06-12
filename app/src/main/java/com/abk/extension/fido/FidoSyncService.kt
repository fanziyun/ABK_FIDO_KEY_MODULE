package com.abk.extension.fido

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlin.concurrent.thread

class FidoSyncService : Service() {
    override fun onCreate() {
        super.onCreate()
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val reason = intent?.getStringExtra(EXTRA_REASON)
            ?: intent?.action
            ?: "service_restart"

        thread(name = "abk-fido-sync-service") {
            val result = MetadataSyncCoordinator(applicationContext).syncNow(reason)
            publishState(result, reason)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(startId)
        }
        return START_STICKY
    }

    override fun onDestroy() = super.onDestroy()

    override fun onBind(intent: Intent?): IBinder? = null

    private fun publishState(result: SyncResult, reason: String) {
        runCatching {
            HostBridge(
                resolver = contentResolver,
                authority = ABK_EXTENSION_DEFAULT_HOST_PROVIDER,
                extensionId = ABK_EXTENSION_DEFAULT_ID
            ).writeState(
                summary = result.userMessage(this),
                success = result.success,
                reason = reason
            )
        }
    }

    private fun buildNotification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.service_channel_name),
                    NotificationManager.IMPORTANCE_MIN
                )
            )
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle(getString(R.string.service_title))
            .setContentText(getString(R.string.service_text))
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_SYNC_NOW = "com.abk.extension.fido.action.SYNC_NOW"
        const val EXTRA_REASON = "reason"

        private const val CHANNEL_ID = "abk_fido_companion"
        private const val NOTIFICATION_ID = 1002
    }
}
