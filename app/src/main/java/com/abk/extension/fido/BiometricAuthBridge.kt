package com.abk.extension.fido

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit

internal object BiometricAuthBridge {
    private val authResultQueue = ArrayBlockingQueue<Boolean>(1)

    @Volatile
    var isAuthenticating: Boolean = false
        private set

    @Volatile
    var expectedRequestId: Int = -1
        private set

    fun begin(requestId: Int) {
        authResultQueue.clear()
        expectedRequestId = requestId
        isAuthenticating = true
    }

    fun finish(success: Boolean) {
        authResultQueue.offer(success)
        isAuthenticating = false
    }

    fun await(timeoutMs: Long): Boolean? {
        return try {
            authResultQueue.poll(timeoutMs, TimeUnit.MILLISECONDS)
        } finally {
            isAuthenticating = false
        }
    }
}
