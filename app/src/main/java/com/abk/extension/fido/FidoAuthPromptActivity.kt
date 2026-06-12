package com.abk.extension.fido

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlin.concurrent.thread

class FidoAuthPromptActivity : FragmentActivity() {
    private var requestId: Int = -1

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        active = true

        requestId = intent.getIntExtra(EXTRA_REQUEST_ID, -1)
        if (requestId <= 0) {
            finish()
            return
        }

        val rpId = intent.getStringExtra(EXTRA_RP_ID).orEmpty()
        val command = intent.getStringExtra(EXTRA_COMMAND).orEmpty()

        val biometricManager = BiometricManager.from(this)
        val canAuth = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            denyWithToast(getString(R.string.auth_biometric_unavailable))
            return
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    approveAndFinish()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    denyWithToast(
                        if (errString.isNotBlank()) errString.toString()
                        else getString(R.string.auth_biometric_denied)
                    )
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.auth_prompt_title))
            .setSubtitle(getString(R.string.auth_prompt_subtitle, rpId.ifBlank { command }))
            .setConfirmationRequired(false)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(promptInfo)
    }

    override fun onDestroy() {
        active = false
        super.onDestroy()
    }

    private fun approveAndFinish() {
        thread(name = "abk-fido-auth-allow") {
            FidoKernelBridge.allow(requestId)
            finishOnUiThread()
        }
    }

    private fun denyWithToast(message: String) {
        Handler(Looper.getMainLooper()).post {
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
        }
        thread(name = "abk-fido-auth-deny") {
            FidoKernelBridge.deny(requestId)
            finishOnUiThread()
        }
    }

    private fun finishOnUiThread() {
        Handler(Looper.getMainLooper()).post { finish() }
    }

    companion object {
        const val EXTRA_REQUEST_ID = "request_id"
        const val EXTRA_COMMAND = "command"
        const val EXTRA_RP_ID = "rp_id"

        @Volatile
        var active: Boolean = false
            private set
    }
}
