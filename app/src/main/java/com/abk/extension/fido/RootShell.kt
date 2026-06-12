package com.abk.extension.fido

import java.io.BufferedReader
import java.io.InputStreamReader

internal object RootShell {
    const val EXIT_MISSING = 3

    data class CommandResult(
        val exitCode: Int,
        val stdout: String,
    ) {
        val success: Boolean
            get() = exitCode == 0
    }

    fun isRootAvailable(): Boolean {
        val result = run("id -u")
        return result.success && result.stdout.trim() == "0"
    }

    fun readFileBase64(path: String): CommandResult {
        return run(
            """
            file=${shellQuote(path)}
            [ -f "${'$'}file" ] || exit $EXIT_MISSING
            base64 "${'$'}file" 2>/dev/null | tr -d '\n'
            """.trimIndent()
        )
    }

    fun readTextFile(path: String): CommandResult {
        return run(
            """
            file=${shellQuote(path)}
            [ -f "${'$'}file" ] || exit $EXIT_MISSING
            cat "${'$'}file"
            """.trimIndent()
        )
    }

    fun writeTextFile(path: String, payload: String): CommandResult {
        return run(
            """
            dst=${shellQuote(path)}
            printf '%s' ${shellQuote(payload)} > "${'$'}dst"
            """.trimIndent()
        )
    }

    fun writeFileBase64(path: String, payloadBase64: String): CommandResult {
        return run(
            """
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
            [ -f "${'$'}src" ] || exit $EXIT_MISSING
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
            [ -f "${'$'}src" ] || exit $EXIT_MISSING
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

    fun run(script: String): CommandResult {
        val process = try {
            ProcessBuilder("su", "-c", script)
                .redirectErrorStream(true)
                .start()
        } catch (t: Throwable) {
            return CommandResult(exitCode = 127, stdout = t.message.orEmpty())
        }

        val stdout = BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
            buildString {
                var first = true
                while (true) {
                    val line = reader.readLine() ?: break
                    if (!first) {
                        append('\n')
                    }
                    append(line)
                    first = false
                }
            }
        }

        val exitCode = process.waitFor()
        return CommandResult(exitCode = exitCode, stdout = stdout)
    }

    private fun shellQuote(value: String): String {
        return "'" + value.replace("'", "'\\''") + "'"
    }
}
