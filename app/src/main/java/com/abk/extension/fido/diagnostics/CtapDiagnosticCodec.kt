package com.abk.extension.fido.diagnostics

import java.io.ByteArrayOutputStream

internal object CtapDiagnosticCodec {
    const val HID_INIT: Int = 0x06
    const val HID_CBOR: Int = 0x10
    const val BROADCAST_CID: Int = 0xffffffff.toInt()

    fun initRequest(nonce: ByteArray): ByteArray {
        require(nonce.size == 8)
        return nonce.copyOf()
    }

    fun cborRequest(payload: ByteArray): ByteArray = payload.copyOf()

    fun getInfoPayload(): ByteArray = byteArrayOf(0x04)

    /** Minimal makeCredential request accepted by the driver's .dummy path. */
    fun dummyMakeCredentialPayload(): ByteArray {
        val out = ByteArrayOutputStream()
        // map(4): clientDataHash, rp, user, pubKeyCredParams
        out.write(0xa4)
        out.write(0x01)
        out.write(0x58)
        out.write(0x20)
        out.write(ByteArray(32))
        out.write(0x02)
        out.write(0xa1)
        writeText(out, "id")
        writeText(out, ".dummy")
        out.write(0x03)
        out.write(0xa2)
        writeText(out, "id")
        out.write(0x42)
        out.write(byteArrayOf(0x01, 0x02))
        writeText(out, "name")
        writeText(out, "dummy")
        out.write(0x04)
        out.write(0x81)
        out.write(0xa2)
        writeText(out, "alg")
        out.write(0x26) // -7, ES256
        writeText(out, "type")
        writeText(out, "public-key")
        return out.toByteArray()
    }

    private fun writeText(out: ByteArrayOutputStream, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        require(bytes.size < 24)
        out.write(0x60 or bytes.size)
        out.write(bytes)
    }
}

internal data class HidFrame(val command: Int, val payload: ByteArray)

internal object CtapHidFraming {
    const val REPORT_SIZE = 64
    private const val INIT_HEADER = 7
    private const val CONT_HEADER = 5

    fun encode(cid: Int, command: Int, payload: ByteArray): List<ByteArray> {
        require(payload.size <= 0xffff)
        val frames = mutableListOf<ByteArray>()
        val first = ByteArray(REPORT_SIZE)
        putU32(first, 0, cid)
        first[4] = (command or 0x80).toByte()
        putU16(first, 5, payload.size)
        val firstLength = minOf(payload.size, REPORT_SIZE - INIT_HEADER)
        payload.copyInto(first, INIT_HEADER, 0, firstLength)
        frames += first
        var offset = firstLength
        var sequence = 0
        while (offset < payload.size) {
            require(sequence < 0x80)
            val frame = ByteArray(REPORT_SIZE)
            putU32(frame, 0, cid)
            frame[4] = sequence.toByte()
            val length = minOf(payload.size - offset, REPORT_SIZE - CONT_HEADER)
            payload.copyInto(frame, CONT_HEADER, offset, offset + length)
            frames += frame
            offset += length
            sequence++
        }
        return frames
    }

    fun decode(frames: List<ByteArray>): HidFrame {
        require(frames.isNotEmpty())
        require(frames.all { it.size == REPORT_SIZE })
        val first = frames.first()
        require(first[4].toInt() and 0x80 != 0)
        val command = first[4].toInt() and 0x7f
        val length = getU16(first, 5)
        val out = ByteArrayOutputStream()
        out.write(first, INIT_HEADER, minOf(length, REPORT_SIZE - INIT_HEADER))
        var expectedSequence = 0
        var index = 1
        while (out.size() < length) {
            require(index < frames.size)
            val frame = frames[index++]
            require(frame[4].toInt() and 0x80 == 0)
            require(frame[4].toInt() and 0x7f == expectedSequence)
            out.write(frame, CONT_HEADER, minOf(length - out.size(), REPORT_SIZE - CONT_HEADER))
            expectedSequence++
        }
        require(out.size() == length)
        return HidFrame(command, out.toByteArray())
    }

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun putU32(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 24).toByte()
        bytes[offset + 1] = (value ushr 16).toByte()
        bytes[offset + 2] = (value ushr 8).toByte()
        bytes[offset + 3] = value.toByte()
    }

    private fun getU16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
}
