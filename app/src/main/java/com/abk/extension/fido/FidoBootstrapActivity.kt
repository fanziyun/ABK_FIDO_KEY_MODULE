package com.abk.extension.fido

import android.app.Activity
import android.content.Intent
import android.os.Bundle

class FidoBootstrapActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startService(
            Intent(this, FidoSyncService::class.java).apply {
                action = FidoSyncService.ACTION_SYNC_NOW
                putExtra(
                    FidoSyncService.EXTRA_REASON,
                    intent?.getStringExtra(ABK_EXTENSION_EXTRA_ID)?.ifBlank { "bootstrap" }
                        ?: "bootstrap"
                )
            }
        )
        finish()
    }
}
