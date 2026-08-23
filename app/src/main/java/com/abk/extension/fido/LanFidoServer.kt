package com.abk.extension.fido

import android.util.Log
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Encrypted LAN CTAP HID relay. Pairing code is the user-visible PSK. */
internal class LanFidoServer(private val pairingCode: String, private val port: Int = 38741) {
    @Volatile private var running = false
    @Volatile private var server: ServerSocket? = null
    @Volatile private var discovery: DatagramSocket? = null
    @Volatile private var lastPairRequestAt = 0L
    private val clients = ConcurrentHashMap.newKeySet<Socket>()
    private val activeClient = AtomicReference<Socket?>(null)

    fun start() {
        if (running) return
        running = true
        startDiscovery()
        Thread {
            runCatching {
                val boundServer = ServerSocket(port)
                server = boundServer
                if (!running) {
                    boundServer.close()
                    if (server === boundServer) server = null
                    return@runCatching
                }
                while (running) {
                    val socket = boundServer.accept()
                    clients += socket
                    Thread {
                        try {
                            serve(socket)
                        } catch (t: Throwable) {
                            if (running) Log.w(TAG, "LAN client closed", t)
                        } finally {
                            clients -= socket
                            activeClient.compareAndSet(socket, null)
                            runCatching { socket.close() }
                        }
                    }.start()
                }
                boundServer.close()
                if (server === boundServer) server = null
            }.onFailure { if (running) Log.e(TAG, "LAN FIDO server stopped", it) }
        }.start()
    }

    fun stop() {
        running = false
        server?.close()
        discovery?.close()
        clients.forEach { runCatching { it.close() } }
        clients.clear()
        activeClient.set(null)
        server = null
        discovery = null
    }

    private fun serve(socket: Socket) {
        socket.use {
            it.soTimeout = HANDSHAKE_TIMEOUT_MS
            // The desktop agent stays connected but silent whenever the USB host
            // is not talking to the key, so rely on TCP keepalive to reap dead
            // peers instead of a short read timeout.
            runCatching { it.keepAlive = true }
            val input = DataInputStream(it.getInputStream()); val output = DataOutputStream(it.getOutputStream())
            val clientNonce = ByteArray(16); input.readFully(clientNonce)
            val serverNonce = ByteArray(16); SecureRandom().nextBytes(serverNonce); output.write(serverNonce); output.flush()
            val key = derive(pairingCode, clientNonce + serverNonce)
            it.soTimeout = SOCKET_TIMEOUT_MS
            CtapHidEndpoint().use { endpoint ->
                var authenticated = false
                // The kernel endpoint has one global TX queue. Read network
                // frames outside the transport lock, then serialize only the
                // complete HID request/response exchange. This keeps an idle
                // LAN connection from blocking the local Credential Manager.
                while (running && !it.isClosed) {
                    val first = awaitFrame(it, input, key) ?: break
                    if (first.size != REPORT_LEN) break
                    val request = readRequest(input, key, first)
                    if (!authenticated) {
                        authenticated = true
                        activeClient.getAndSet(it)?.let { previous ->
                            if (previous !== it) {
                                Log.i(TAG, "replacing previous authenticated LAN CTAP session")
                                runCatching { previous.close() }
                            }
                        }
                    }
                    CtapHidEndpoint.withTransportLock {
                        if (activeClient.get() !== it) {
                            throw IOException("LAN CTAP session was superseded")
                        }
                        request.forEach(endpoint::writePacket)
                        if ((first[4].toInt() and 0x7f) != HID_CANCEL) {
                            relayResponse(
                                endpoint = endpoint,
                                output = output,
                                key = key,
                                requestCid = readCid(first),
                                requestCommand = first[4].toInt() and 0x7f,
                                requestLength = ((first[5].toInt() and 0xff) shl 8) or
                                    (first[6].toInt() and 0xff),
                                requestNonce = first.copyOfRange(7, 15),
                            )
                        }
                    }
                }
            }
        }
    }

    /**
     * Wait for the first frame of the next request, tolerating idle periods.
     * The desktop agent only sends when the USB host issues a CTAP request, so
     * a read timeout with no frame started means "still idle", not "failed".
     * A timeout once the frame has started is a real protocol failure and is
     * propagated by [readFrame].
     */
    private fun awaitFrame(socket: Socket, input: DataInputStream, key: ByteArray): ByteArray? {
        while (running && !socket.isClosed) {
            val firstLengthByte = try {
                input.read()
            } catch (_: SocketTimeoutException) {
                continue
            }
            if (firstLengthByte < 0) return null
            return readFrame(input, key, firstLengthByte)
        }
        return null
    }

    /** Read one complete HID request, including continuation packets. */
    private fun readRequest(
        input: DataInputStream,
        key: ByteArray,
        first: ByteArray,
    ): List<ByteArray> {
        val packets = ArrayList<ByteArray>()
        packets += first
        val header = first[4].toInt() and 0xff
        if ((header and 0x80) == 0) {
            throw IOException("CTAP request starts with continuation packet")
        }
        val expected = ((first[5].toInt() and 0xff) shl 8) or (first[6].toInt() and 0xff)
        if (expected > MAX_MESSAGE_LEN) {
            throw IOException("invalid CTAP request length=$expected")
        }
        var remaining = expected - minOf(expected, FIRST_PAYLOAD_LEN)
        var sequence = 0
        val cid = readCid(first)
        while (remaining > 0) {
            val packet = readFrame(input, key)
                ?: throw IOException("LAN client closed during CTAP request")
            if (packet.size != REPORT_LEN) throw IOException("invalid CTAP continuation size")
            if (readCid(packet) != cid) throw IOException("CTAP request CID changed mid-message")
            val packetSequence = packet[4].toInt() and 0xff
            if ((packetSequence and 0x80) != 0 || packetSequence != sequence) {
                throw IOException("invalid CTAP request sequence=$packetSequence expected=$sequence")
            }
            packets += packet
            remaining -= minOf(remaining, CONTINUATION_PAYLOAD_LEN)
            sequence++
        }
        return packets
    }

    /**
     * Forward exactly one HID response message. Keepalive packets are
     * forwarded while the authenticator waits for user approval. Packets for
     * another CID are consumed and discarded as stale output left by an older
     * session, rather than being sent to the current desktop client.
     */
    private fun relayResponse(
        endpoint: CtapHidEndpoint,
        output: DataOutputStream,
        key: ByteArray,
        requestCid: Int,
        requestCommand: Int,
        requestLength: Int,
        requestNonce: ByteArray,
    ) {
        while (true) {
            val first = endpoint.readPacket()
            val cid = readCid(first)
            val header = first[4].toInt() and 0xff
            if ((header and 0x80) == 0) continue

            val command = header and 0x7f
            val expected = ((first[5].toInt() and 0xff) shl 8) or (first[6].toInt() and 0xff)
            if (expected > MAX_MESSAGE_LEN) {
                throw IOException("invalid CTAP response length=$expected")
            }
            val initNonceMatches = requestCid != BROADCAST_CID || requestCommand != HID_INIT ||
                command == HID_ERROR ||
                (requestLength >= 8 && first.copyOfRange(7, 15).contentEquals(requestNonce))
            val commandMatches = command == requestCommand ||
                command == HID_KEEPALIVE || command == HID_ERROR
            val matches = cid == requestCid && initNonceMatches && commandMatches
            if (matches) writeFrame(output, key, first)

            // CTAP HID KEEPALIVE is a standalone initialization packet. It
            // does not terminate the response message we are waiting for.
            if (command == HID_KEEPALIVE) continue

            var remaining = expected - minOf(expected, FIRST_PAYLOAD_LEN)
            var sequence = 0
            while (remaining > 0) {
                val packet = endpoint.readPacket()
                val packetCid = readCid(packet)
                val packetHeader = packet[4].toInt() and 0xff
                if ((packetHeader and 0x80) != 0) {
                    if (packetCid == requestCid && (packetHeader and 0x7f) == HID_KEEPALIVE) {
                        writeFrame(output, key, packet)
                    }
                    continue
                }
                if (packetCid != cid || packetHeader != sequence) {
                    throw IOException(
                        "unexpected CTAP HID continuation cid=0x${Integer.toHexString(packetCid)} seq=$packetHeader expected=$sequence"
                    )
                }
                if (matches) writeFrame(output, key, packet)
                remaining -= minOf(remaining, CONTINUATION_PAYLOAD_LEN)
                sequence++
            }
            if (matches) return
        }
    }

    private fun readCid(packet: ByteArray): Int =
        ((packet[0].toInt() and 0xff) shl 24) or
            ((packet[1].toInt() and 0xff) shl 16) or
            ((packet[2].toInt() and 0xff) shl 8) or
            (packet[3].toInt() and 0xff)

    private fun startDiscovery() {
        Thread {
            runCatching {
                val discoverySocket = DatagramSocket(DISCOVERY_PORT).apply { broadcast = true }
                discovery = discoverySocket
                if (!running) {
                    discoverySocket.close()
                    if (discovery === discoverySocket) discovery = null
                    return@runCatching
                }
                val buf = ByteArray(64)
                while (running) {
                    val packet = DatagramPacket(buf, buf.size); discoverySocket.receive(packet)
                    val message = String(packet.data, 0, packet.length)
                    if (message == DISCOVER) {
                        val reply = HERE.toByteArray()
                        discoverySocket.send(DatagramPacket(reply, reply.size, packet.address, packet.port))
                    } else if (message == PAIR_REQUEST) {
                        val now = System.currentTimeMillis()
                        if (now - lastPairRequestAt >= PAIR_REQUEST_COOLDOWN_MS) {
                            lastPairRequestAt = now
                            val launch = RootShell.launchPairingCodeActivity()
                            if (!launch.success) Log.w(TAG, "pairing activity launch failed: ${launch.stdout}")
                        }
                        val reply = PAIR_ACK.toByteArray()
                        discoverySocket.send(DatagramPacket(reply, reply.size, packet.address, packet.port))
                    }
                }
                discoverySocket.close()
                if (discovery === discoverySocket) discovery = null
            }.onFailure { if (running) Log.w(TAG, "LAN discovery stopped", it) }
        }.start()
    }

    private fun derive(password: String, salt: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256"); mac.init(SecretKeySpec(password.toByteArray(), "HmacSHA256"))
        var t = mac.doFinal(salt + byteArrayOf(0, 0, 0, 1)); val out = t.copyOf()
        repeat(99_999) { t = mac.doFinal(t); for (i in out.indices) out[i] = (out[i].toInt() xor t[i].toInt()).toByte() }
        return out
    }

    private fun readFrame(input: DataInputStream, key: ByteArray, firstLengthByte: Int = -1): ByteArray? {
        val len = if (firstLengthByte < 0) input.readInt() else readIntTail(input, firstLengthByte)
        if (len !in 1..4096) return null
        val nonce = ByteArray(12); input.readFully(nonce); val body = ByteArray(len); input.readFully(body)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); return cipher.doFinal(body)
    }

    /** Complete a big-endian length whose most significant byte was already read. */
    private fun readIntTail(input: DataInputStream, firstLengthByte: Int): Int {
        val rest = ByteArray(3)
        input.readFully(rest)
        return ((firstLengthByte and 0xff) shl 24) or ((rest[0].toInt() and 0xff) shl 16) or
            ((rest[1].toInt() and 0xff) shl 8) or (rest[2].toInt() and 0xff)
    }

    private fun writeFrame(output: DataOutputStream, key: ByteArray, payload: ByteArray) {
        val nonce = ByteArray(12); SecureRandom().nextBytes(nonce); val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); val body = cipher.doFinal(payload)
        output.writeInt(body.size); output.write(nonce); output.write(body); output.flush()
    }

    companion object {
        private const val TAG = "AbkLanFido"
        private const val DISCOVERY_PORT = 38740
        private const val HANDSHAKE_TIMEOUT_MS = 5_000
        private const val SOCKET_TIMEOUT_MS = 60_000
        private const val REPORT_LEN = 64
        private const val FIRST_PAYLOAD_LEN = 57
        private const val CONTINUATION_PAYLOAD_LEN = 59
        private const val MAX_MESSAGE_LEN = 2048
        private const val BROADCAST_CID = -1
        private const val HID_INIT = 0x06
        private const val HID_KEEPALIVE = 0x3b
        private const val HID_ERROR = 0x3f
        private const val HID_CANCEL = 0x11
        private const val PAIR_REQUEST_COOLDOWN_MS = 2_000L
        private const val DISCOVER = "ABK_FIDO_DISCOVER_V1"
        private const val HERE = "ABK_FIDO_HERE_V1"
        private const val PAIR_REQUEST = "ABK_FIDO_PAIR_REQUEST_V1"
        private const val PAIR_ACK = "ABK_FIDO_PAIR_ACK_V1"
    }
}
