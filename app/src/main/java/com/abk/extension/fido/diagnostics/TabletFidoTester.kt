package com.abk.extension.fido.diagnostics

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbRequest
import java.nio.ByteBuffer

internal data class UsbFidoCandidate(
    val device: UsbDevice,
    val usbInterface: UsbInterface,
    val input: UsbEndpoint,
    val output: UsbEndpoint,
) {
    val label: String
        get() = "${device.manufacturerName ?: "USB"} ${device.productName ?: device.deviceName} " +
            "(${device.vendorId.toString(16)}:${device.productId.toString(16)})"
}

internal data class TabletTestResult(
    val report: String,
    val passed: Boolean,
)

internal class TabletFidoTester(
    private val connection: UsbDeviceConnection,
    private val candidate: UsbFidoCandidate,
    private val readTimeoutMs: Int = 60_000,
) {
    fun run(includeFingerprint: Boolean, onStage: (String) -> Unit): TabletTestResult {
        val report = StringBuilder()
        fun log(line: String) {
            report.append(line).append('\n')
        }
        log("role=tablet")
        log("device=${candidate.label}")
        log("interface=${candidate.usbInterface.id} class=${candidate.usbInterface.interfaceClass} " +
            "subclass=${candidate.usbInterface.interfaceSubclass} protocol=${candidate.usbInterface.interfaceProtocol}")
        log("input=${candidate.input.address} max=${candidate.input.maxPacketSize} " +
            "output=${candidate.output.address} max=${candidate.output.maxPacketSize}")
        return try {
            onStage("USB interface claimed")
            if (!connection.claimInterface(candidate.usbInterface, true)) {
                log("FAIL claimInterface=false")
                return TabletTestResult(report.toString(), false)
            }
            val nonce = byteArrayOf(0x41, 0x42, 0x4b, 0x46, 0x49, 0x44, 0x4f, 0x31)
            val cid = CtapDiagnosticCodec.BROADCAST_CID
            onStage("Sending CTAPHID INIT")
            val initResponse = exchange(cid, CtapDiagnosticCodec.HID_INIT, nonce)
            log("init=${initResponse.payload.toHex()}")
            if (initResponse.payload.size < 17) {
                log("FAIL short INIT response")
                return TabletTestResult(report.toString(), false)
            }
            val assignedCid = readU32(initResponse.payload, 8)
            log("assignedCid=0x${assignedCid.toUInt().toString(16)}")
            onStage("Sending authenticatorGetInfo")
            val info = exchange(assignedCid, CtapDiagnosticCodec.HID_CBOR, CtapDiagnosticCodec.getInfoPayload())
            log("getInfo=${info.payload.toHex()}")
            if (info.payload.isEmpty() || info.payload[0].toInt() != 0) {
                log("FAIL getInfo status=${info.payload.firstOrNull()?.toInt() ?: -1}")
                return TabletTestResult(report.toString(), false)
            }
            log("PASS CTAPHID INIT + authenticatorGetInfo")
            if (includeFingerprint) {
                onStage("Waiting for phone fingerprint")
                val dummy = exchange(assignedCid, CtapDiagnosticCodec.HID_CBOR, CtapDiagnosticCodec.dummyMakeCredentialPayload())
                log("dummyMakeCredential=${dummy.payload.toHex()}")
                log("PASS phone responded to dummy request")
            }
            TabletTestResult(report.toString(), true)
        } catch (t: Throwable) {
            log("FAIL ${t.javaClass.simpleName}: ${t.message}")
            TabletTestResult(report.toString(), false)
        } finally {
            connection.releaseInterface(candidate.usbInterface)
        }
    }

    private fun exchange(cid: Int, command: Int, payload: ByteArray): HidFrame {
        val deadline = System.currentTimeMillis() + readTimeoutMs
        val frames = CtapHidFraming.encode(cid, command, payload)
        for (frame in frames) {
            transfer(candidate.output, frame, write = true)
        }
        val responseFrames = mutableListOf<ByteArray>()
        val first = readFrame(deadline)
        responseFrames += first
        val length = ((first[5].toInt() and 0xff) shl 8) or (first[6].toInt() and 0xff)
        val remaining = (length - 57).coerceAtLeast(0)
        val continuationFrames = (remaining + 58) / 59
        val needed = 1 + continuationFrames
        while (responseFrames.size < needed) {
            responseFrames += readFrame(deadline)
        }
        return CtapHidFraming.decode(responseFrames)
    }

    private fun readFrame(deadline: Long): ByteArray {
        val frame = ByteArray(CtapHidFraming.REPORT_SIZE)
        val remainingMs = (deadline - System.currentTimeMillis()).coerceAtLeast(100L)
        transfer(candidate.input, frame, write = false, timeoutMs = remainingMs)
        return frame
    }

    private fun transfer(endpoint: UsbEndpoint, data: ByteArray, write: Boolean, timeoutMs: Long = 3500L) {
        val request = UsbRequest()
        check(request.initialize(connection, endpoint)) { "UsbRequest initialize failed" }
        try {
            val buffer = ByteBuffer.allocate(data.size)
            if (write) buffer.put(data).flip()
            check(request.queue(buffer)) { "UsbRequest queue failed" }
            val completed = connection.requestWait(timeoutMs)
                ?: throw IllegalStateException("USB transfer timed out after ${timeoutMs}ms")
            check(completed === request) { "USB request mismatch" }
            if (!write) {
                buffer.flip()
                val length = minOf(buffer.remaining(), data.size)
                buffer.get(data, 0, length)
                check(length == data.size) { "USB read returned $length/${data.size}" }
            }
        } finally {
            request.close()
        }
    }

    private fun readU32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() shl 24) or
            ((bytes[offset + 1].toInt() and 0xff) shl 16) or
            ((bytes[offset + 2].toInt() and 0xff) shl 8) or
            (bytes[offset + 3].toInt() and 0xff)
}

internal fun findUsbFidoCandidates(device: UsbDevice): List<UsbFidoCandidate> {
    val result = mutableListOf<UsbFidoCandidate>()
    for (index in 0 until device.interfaceCount) {
        val intf = device.getInterface(index)
        if (intf.interfaceClass != UsbConstants.USB_CLASS_HID) continue
        var input: UsbEndpoint? = null
        var output: UsbEndpoint? = null
        for (endpointIndex in 0 until intf.endpointCount) {
            val endpoint = intf.getEndpoint(endpointIndex)
            if (endpoint.type != UsbConstants.USB_ENDPOINT_XFER_INT) continue
            if (endpoint.direction == UsbConstants.USB_DIR_IN) input = endpoint
            if (endpoint.direction == UsbConstants.USB_DIR_OUT) output = endpoint
        }
        if (input != null && output != null) {
            result += UsbFidoCandidate(device, intf, input, output)
        }
    }
    return result
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
