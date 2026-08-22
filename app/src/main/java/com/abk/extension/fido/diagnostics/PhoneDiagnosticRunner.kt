package com.abk.extension.fido.diagnostics

import android.content.Context
import android.content.Intent
import android.os.Build
import com.abk.extension.fido.FidoSyncService
import com.abk.extension.fido.RootShell
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

internal data class PhoneTestResult(
    val report: String,
    val passed: Boolean,
)

internal object PhoneDiagnosticRunner {
    private val SYSFS_NODES = listOf(
        "enabled", "bound", "hid_dev", "udc", "auth_gate_enabled", "auth_pending",
        "auth_request_id", "auth_context", "last_error", "last_trace",
        "credential_count", "store_generation",
    )

    fun run(context: Context, onStage: (String) -> Unit): PhoneTestResult {
        val report = StringBuilder()
        fun append(title: String, result: RootShell.CommandResult) {
            report.append("\n=== ").append(title).append(" ===\n")
            report.append("exit=").append(result.exitCode).append('\n')
            report.append(result.stdout.trim()).append('\n')
        }
        report.append("ABK FIDO diagnostic report\n")
        report.append("role=phone\n")
        report.append("time=").append(timestamp()).append('\n')
        report.append("android=").append(Build.VERSION.RELEASE).append(" sdk=").append(Build.VERSION.SDK_INT).append('\n')

        onStage("Checking root")
        val root = RootShell.run("id; uname -a")
        append("root and kernel", root)
        if (!RootShell.isRootAvailable()) {
            report.append("FAIL root unavailable\n")
            return PhoneTestResult(report.toString(), false)
        }

        onStage("Starting companion service")
        runCatching {
            val intent = Intent(context, FidoSyncService::class.java).apply {
                action = FidoSyncService.ACTION_SYNC_NOW
                putExtra(FidoSyncService.EXTRA_REASON, "diagnostic")
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent)
            else context.startService(intent)
            report.append("serviceStart=ok\n")
        }.onFailure { report.append("serviceStart=failed ${it.message}\n") }

        onStage("Reading FIDO state")
        for (node in SYSFS_NODES) {
            append("sysfs $node", RootShell.readTextFile("/sys/kernel/abk_fido_key/$node"))
        }
        append(
            "USB properties",
            RootShell.run(
                """
                echo "sys.usb.config=$(getprop sys.usb.config)"
                echo "sys.usb.state=$(getprop sys.usb.state)"
                echo "persist.sys.usb.config=$(getprop persist.sys.usb.config)"
                """.trimIndent()
            )
        )
        append("HID device", RootShell.run("ls -l /dev/hidg* 2>/dev/null || true"))
        append(
            "gadget links",
            RootShell.run(
                "find /config/usb_gadget -maxdepth 4 -type l -print -exec readlink {} \\; 2>/dev/null || true"
            )
        )
        append(
            "companion service",
            RootShell.run("dumpsys activity services com.abk.extension.fido | grep -A12 -B3 FidoSyncService || true")
        )
        onStage("Collecting kernel log")
        append(
            "filtered dmesg",
            RootShell.run(
                "dmesg | grep -E 'abk_fido_key|auth_|ctap|usb|gadget|dwc3|hid' | tail -600"
            )
        )
        append(
            "companion logcat",
            RootShell.run("logcat -d -v threadtime -s AbkFidoCompanion:V AndroidRuntime:E | tail -300")
        )
        val enabled = RootShell.readTextFile("/sys/kernel/abk_fido_key/enabled").stdout.trim() == "1"
        val bound = RootShell.readTextFile("/sys/kernel/abk_fido_key/bound").stdout.trim() == "1"
        report.append("\nRESULT enabled=").append(enabled).append(" bound=").append(bound).append('\n')
        return PhoneTestResult(report.toString(), enabled && bound)
    }

    fun saveToDownloads(report: String, prefix: String): RootShell.CommandResult {
        val safePrefix = prefix.replace(Regex("[^A-Za-z0-9_-]"), "_")
        val path = "/sdcard/Download/${safePrefix}_${fileTimestamp()}.txt"
        val encoded = android.util.Base64.encodeToString(report.toByteArray(Charsets.UTF_8), android.util.Base64.NO_WRAP)
        val result = RootShell.run(
            """
            mkdir -p /sdcard/Download
            printf '%s' '$encoded' | base64 -d > '$path'
            chmod 0644 '$path'
            echo '$path'
            """.trimIndent()
        )
        return result
    }

    private fun timestamp(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.US).format(Date())

    private fun fileTimestamp(): String =
        SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
}
