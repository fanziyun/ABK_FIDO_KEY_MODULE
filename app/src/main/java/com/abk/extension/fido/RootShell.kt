package com.abk.extension.fido

import com.topjohnwu.superuser.Shell

internal object RootShell {
    private const val BOOT_SCRIPT_PATH = "/data/adb/service.d/abk-fido-companion.sh"

    data class CommandResult(
        val exitCode: Int,
        val stdout: String,
    ) {
        val success: Boolean
            get() = exitCode == 0
    }

    @Volatile
    private var initialized = false
    private val initLock = Any()

    fun init() {
        if (initialized) return
        synchronized(initLock) {
            if (initialized) return
            Shell.enableVerboseLogging = false
            Shell.setDefaultBuilder(
                Shell.Builder.create()
                    .setFlags(Shell.FLAG_MOUNT_MASTER or Shell.FLAG_REDIRECT_STDERR)
                    .setTimeout(10)
            )
            initialized = true
        }
    }

    fun isRootAvailable(): Boolean {
        val result = run("id -u")
        return result.success && result.stdout.trim() == "0"
    }

    fun readFileBase64(path: String): CommandResult {
        return run(
            """
            file=${shellQuote(path)}
            [ -f "${'$'}file" ] || exit 3
            base64 "${'$'}file" 2>/dev/null | tr -d '\n'
            """.trimIndent()
        )
    }

    fun readTextFile(path: String): CommandResult {
        return run(
            """
            file=${shellQuote(path)}
            [ -f "${'$'}file" ] || exit 3
            cat "${'$'}file"
            """.trimIndent()
        )
    }

    fun writeTextFile(path: String, payload: String): CommandResult {
        return run(
            """
            set -e
            dst=${shellQuote(path)}
            printf '%s' ${shellQuote(payload)} > "${'$'}dst"
            """.trimIndent()
        )
    }

    fun writeFileBase64(path: String, payloadBase64: String): CommandResult {
        return run(
            """
            set -e
            dst=${shellQuote(path)}
            printf '%s' ${shellQuote(payloadBase64)} | base64 -d > "${'$'}dst"
            chmod 0600 "${'$'}dst" 2>/dev/null || true
            restorecon "${'$'}dst" 2>/dev/null || true
            """.trimIndent()
        )
    }

    fun copyFileToMetadata(srcPath: String, dstPath: String): CommandResult {
        return run(
            """
            src=${shellQuote(srcPath)}
            dst=${shellQuote(dstPath)}
            [ -f "${'$'}src" ] || exit 3
            cp -f "${'$'}src" "${'$'}dst"
            chmod 0600 "${'$'}dst" 2>/dev/null || true
            restorecon "${'$'}dst" 2>/dev/null || true
            """.trimIndent()
        )
    }

    fun copyFileFromMetadata(srcPath: String, dstPath: String, ownerUid: Int): CommandResult {
        return run(
            """
            src=${shellQuote(srcPath)}
            dst=${shellQuote(dstPath)}
            [ -f "${'$'}src" ] || exit 3
            cp -f "${'$'}src" "${'$'}dst"
            chown ${ownerUid}:${ownerUid} "${'$'}dst" 2>/dev/null || true
            chmod 0600 "${'$'}dst" 2>/dev/null || true
            """.trimIndent()
        )
    }

    fun launchAbkExtensionManager(): CommandResult {
        return run(
            """
            am start -n 'com.abk.kernel/com.abk.kernel.extensions.AbkExtensionManagerActivity' \
              --es 'com.abk.kernel.extra.EXTENSION_ID' 'abk_fido_store' \
              --ez 'bootstrap_mode' 'true'
            """.trimIndent()
        )
    }

    fun ensureBootStartScript(): CommandResult {
        val scriptBody = """
            #!/system/bin/sh
            (
              i=0
              while [ "${'$'}i" -lt 120 ]; do
                if /system/bin/cmd user is-user-unlocked 0 2>/dev/null | /system/bin/grep -qi true; then
                  /system/bin/am start-foreground-service -n com.abk.extension.fido/.FidoSyncService --es reason service_d_boot >/dev/null 2>&1
                  exit 0
                fi
                i=$((i + 1))
                /system/bin/sleep 5
              done
            ) &
        """.trimIndent()
        return run(
            """
            set -e
            dir='/data/adb/service.d'
            dst=${shellQuote(BOOT_SCRIPT_PATH)}
            mkdir -p "${'$'}dir"
            cat > "${'$'}dst" <<'EOF'
            $scriptBody
            EOF
            chmod 0755 "${'$'}dst"
            restorecon "${'$'}dst" 2>/dev/null || true
            """.trimIndent()
        )
    }

    fun launchFidoAuthPromptActivity(
        requestId: Int,
        command: String,
        rpId: String,
    ): CommandResult {
        return run(
            """
            am start -n 'com.abk.extension.fido/.FidoAuthPromptActivity' \
              --ei 'request_id' ${requestId} \
              --es 'command' ${shellQuote(command)} \
              --es 'rp_id' ${shellQuote(rpId)}
            """.trimIndent()
        )
    }

    fun run(script: String): CommandResult {
        init()
        return try {
            val output = mutableListOf<String>()
            val result = createRootShell(timeoutSeconds = 10L).use { shell ->
                shell.newJob()
                    .to(output, output)
                    .add(script)
                    .exec()
            }
            CommandResult(
                exitCode = if (result.isSuccess) 0 else 1,
                stdout = output.joinToString("\n")
            )
        } catch (t: Throwable) {
            CommandResult(exitCode = 127, stdout = t.message.orEmpty())
        }
    }

    private fun createRootShell(timeoutSeconds: Long): Shell {
        val builder = Shell.Builder.create()
            .setFlags(Shell.FLAG_MOUNT_MASTER or Shell.FLAG_REDIRECT_STDERR)
            .setTimeout(timeoutSeconds)
        val candidates = arrayOf(
            arrayOf("/data/adb/ksud", "debug", "su", "-g"),
            arrayOf("ksud", "debug", "su", "-g"),
            arrayOf("su", "-mm"),
            arrayOf("su")
        )
        candidates.forEach { command ->
            try {
                val shell = builder.build(*command)
                if (isShellRoot(shell)) return shell
                shell.close()
            } catch (_: Throwable) {
            }
        }

        val shell = builder.build()
        if (isShellRoot(shell)) return shell
        shell.close()
        throw IllegalStateException("Root shell unavailable")
    }

    private fun isShellRoot(shell: Shell): Boolean {
        val output = mutableListOf<String>()
        val result = shell.newJob()
            .to(output, output)
            .add("id -u")
            .exec()
        return result.isSuccess && output.firstOrNull()?.trim() == "0"
    }

    private fun shellQuote(value: String): String {
        return "'" + value.replace("'", "'\\''") + "'"
    }
}
