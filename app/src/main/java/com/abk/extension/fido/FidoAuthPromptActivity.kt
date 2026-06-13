package com.abk.extension.fido

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

class FidoAuthPromptActivity : FragmentActivity() {
    private var requestId: Int = -1
    private var isResultSent = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestId = intent.getIntExtra(EXTRA_REQUEST_ID, -1)
        if (requestId <= 0 || requestId != BiometricAuthBridge.expectedRequestId) {
            finish()
            return
        }

        val rpId = intent.getStringExtra(EXTRA_RP_ID).orEmpty()
        val command = intent.getStringExtra(EXTRA_COMMAND).orEmpty()

        val biometricManager = BiometricManager.from(this)
        val authenticators =
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        val canAuth = biometricManager.canAuthenticate(authenticators)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            sendResultAndFinish(false, getString(R.string.auth_biometric_unavailable))
            return
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    sendResultAndFinish(true, null)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    sendResultAndFinish(
                        false,
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
            .setAllowedAuthenticators(authenticators)
            .build()
        prompt.authenticate(promptInfo)
    }

    override fun onDestroy() {
        super.onDestroy()
        sendResultAndFinish(false, null)
    }

    private fun sendResultAndFinish(success: Boolean, message: String?) {
        if (isResultSent) return
        isResultSent = true
        if (!message.isNullOrBlank()) {
            Handler(Looper.getMainLooper()).post {
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            }
        }
        BiometricAuthBridge.finish(success)
        finish()
    }

    companion object {
        const val EXTRA_REQUEST_ID = "request_id"
        const val EXTRA_COMMAND = "command"
        const val EXTRA_RP_ID = "rp_id"
    }
}
