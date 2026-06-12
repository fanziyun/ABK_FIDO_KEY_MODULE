package com.abk.extension.fido

import android.content.ContentResolver
import android.net.Uri
import android.os.Bundle
import org.json.JSONObject

internal class HostBridge(
    private val resolver: ContentResolver,
    authority: String,
    private val extensionId: String,
) {
    private val uri: Uri = Uri.parse("content://$authority")

    fun writeState(summary: String, success: Boolean, reason: String): Result<Unit> {
        val payload = JSONObject()
            .put("oobe_completed", true)
            .put("summary", summary)
            .put(
                "settings",
                JSONObject()
                    .put("last_reason", reason)
                    .put("sync_success", success)
            )
            .toString()

        val bundle = resolver.call(
            uri,
            "put_extension_state",
            extensionId,
            Bundle().apply {
                putString(ABK_EXTENSION_EXTRA_ID, extensionId)
                putString("state_json", payload)
            }
        ) ?: return Result.failure(IllegalStateException("null bundle"))

        return if (bundle.getBoolean("success")) {
            Result.success(Unit)
        } else {
            Result.failure(IllegalStateException(bundle.getString("error").orEmpty()))
        }
    }
}
