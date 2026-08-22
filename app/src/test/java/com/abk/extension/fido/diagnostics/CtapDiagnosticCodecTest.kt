package com.abk.extension.fido.diagnostics

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CtapDiagnosticCodecTest {
    @Test
    fun initRoundTripUsesEightByteNonce() {
        val nonce = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val frames = CtapHidFraming.encode(0xffffffff.toInt(), CtapDiagnosticCodec.HID_INIT, nonce)
        val decoded = CtapHidFraming.decode(frames)
        assertEquals(CtapDiagnosticCodec.HID_INIT, decoded.command)
        assertArrayEquals(nonce, decoded.payload)
    }

    @Test
    fun cborPayloadFragmentsAndReassembles() {
        val payload = ByteArray(200) { it.toByte() }
        val frames = CtapHidFraming.encode(0x01020304, CtapDiagnosticCodec.HID_CBOR, payload)
        assertTrue(frames.size > 3)
        assertEquals(64, frames.first().size)
        assertArrayEquals(payload, CtapHidFraming.decode(frames).payload)
    }

    @Test(expected = IllegalArgumentException::class)
    fun continuationSequenceMustStartAtZero() {
        val frames = CtapHidFraming.encode(0x01020304, CtapDiagnosticCodec.HID_CBOR, ByteArray(100))
        frames[1][4] = 1
        CtapHidFraming.decode(frames)
    }

    @Test
    fun dummyRequestContainsSentinelValues() {
        val payload = CtapDiagnosticCodec.dummyMakeCredentialPayload()
        val text = payload.toString(Charsets.ISO_8859_1)
        assertEquals(0xA4.toByte(), payload[0])
        assertTrue(text.contains(".dummy"))
        assertTrue(text.contains("dummy"))
        assertTrue(text.contains("public-key"))
    }
}
