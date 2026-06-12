package com.abk.extension.fido

private const val SYSFS_BASE = "/sys/kernel/abk_fido_key"
private const val AUTH_PENDING_PATH = "$SYSFS_BASE/auth_pending"
private const val AUTH_REQUEST_ID_PATH = "$SYSFS_BASE/auth_request_id"
private const val AUTH_CONTEXT_PATH = "$SYSFS_BASE/auth_context"
private const val AUTH_DECISION_PATH = "$SYSFS_BASE/auth_decision"
private const val LAST_ERROR_PATH = "$SYSFS_BASE/last_error"
private const val LAST_TRACE_PATH = "$SYSFS_BASE/last_trace"

internal data class PendingAuthRequest(
    val requestId: Int,
    val command: String,
    val rpId: String,
    val uv: Boolean,
    val rk: Boolean,
)

internal object FidoKernelBridge {
    fun readPendingAuthRequest(): PendingAuthRequest? {
        val pending = RootShell.readTextFile(AUTH_PENDING_PATH)
        if (!pending.success || pending.stdout.trim() != "1") return null

        val requestId = RootShell.readTextFile(AUTH_REQUEST_ID_PATH)
            .stdout
            .trim()
            .toIntOrNull()
            ?: return null
        val context = RootShell.readTextFile(AUTH_CONTEXT_PATH)
        if (!context.success) return null

        val raw = context.stdout.trim()
        val values = raw
            .split(' ')
            .mapNotNull { token ->
                val idx = token.indexOf('=')
                if (idx <= 0) null else token.substring(0, idx) to token.substring(idx + 1)
            }
            .toMap()

        return PendingAuthRequest(
            requestId = requestId,
            command = values["cmd"].orEmpty(),
            rpId = values["rp"].orEmpty(),
            uv = values["uv"] == "1",
            rk = values["rk"] == "1",
        )
    }

    fun allow(requestId: Int): RootShell.CommandResult =
        RootShell.writeTextFile(AUTH_DECISION_PATH, "allow $requestId\n")

    fun deny(requestId: Int): RootShell.CommandResult =
        RootShell.writeTextFile(AUTH_DECISION_PATH, "deny $requestId\n")

    fun readLastError(): String =
        RootShell.readTextFile(LAST_ERROR_PATH).stdout.trim()

    fun readLastTrace(): String =
        RootShell.readTextFile(LAST_TRACE_PATH).stdout.trim()
}
