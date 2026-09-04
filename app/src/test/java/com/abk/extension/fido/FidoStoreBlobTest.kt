package com.abk.extension.fido

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.zip.CRC32

/**
 * The blob codec is the one place where a wrong byte offset silently corrupts
 * the key store, so the round trip through the driver's exact layout is checked
 * here rather than on the phone.
 */
class FidoStoreBlobTest {

    private fun record(slot: Int, rpId: String, name: String = "alice", display: String = "Alice") =
        FidoCredentialRecord(
            slot = slot,
            resident = true,
            userIdLen = 4,
            credId = ByteArray(32) { (it + slot).toByte() },
            userId = ByteArray(64) { if (it < 4) (it + 1).toByte() else 0 },
            rpId = rpId,
            userName = name,
            userDisplay = display,
            privKey = ByteArray(32) { (0x40 + it).toByte() },
            pubKey = ByteArray(64) { (0x80 + it).toByte() },
            hmacSecret = ByteArray(32) { (0xa0 + it).toByte() },
        )

    private fun writeIntLe(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xff).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xff).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xff).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xff).toByte()
    }

    private fun readIntLe(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)

    @Test
    fun emptyStoreHasTheSizeTheDriverReads() {
        val bytes = FidoStoreBlob.empty().toBytes()
        assertEquals(FidoStoreBlob.SIZE, bytes.size)
        assertEquals(FidoStoreBlob.HEADER_SIZE + FidoStoreBlob.CRED_SIZE * FidoStoreBlob.MAX_CREDS, bytes.size)
        assertEquals(FidoStoreBlob.MAX_CREDS, FidoStoreBlob.empty().freeSlots())
    }

    @Test
    fun sealedBlobCarriesTheCrcTheDriverComputes() {
        val bytes = FidoStoreBlob.empty().withCredential(record(0, "example.com"))!!.toBytes()
        // abk_fido_store_crc32() is a plain zlib CRC-32 over sign_count..end.
        val crc = CRC32().apply { update(bytes, 12, bytes.size - 12) }.value.toInt()
        val stored = (bytes[8].toInt() and 0xff) or ((bytes[9].toInt() and 0xff) shl 8) or
            ((bytes[10].toInt() and 0xff) shl 16) or ((bytes[11].toInt() and 0xff) shl 24)
        assertEquals(crc, stored)
        assertNotNull(FidoStoreBlob.parse(bytes))
    }

    @Test
    fun credentialSurvivesAWriteAndReadBack() {
        val original = record(0, "example.com", name = "alice@example.com", display = "Alice Example")
        val stored = FidoStoreBlob.parse(
            FidoStoreBlob.empty().withCredential(original)!!.toBytes()
        )!!.credentials()
        assertEquals(1, stored.size)
        val read = stored[0]
        assertEquals(0, read.slot)
        assertEquals("example.com", read.rpId)
        assertEquals("alice@example.com", read.userName)
        assertEquals("Alice Example", read.userDisplay)
        assertEquals(4, read.userIdLen)
        assertTrue(read.resident)
        assertEquals(original.credId.toList(), read.credId.toList())
        assertEquals(original.privKey.toList(), read.privKey.toList())
        assertEquals(original.pubKey.toList(), read.pubKey.toList())
        assertEquals(original.hmacSecret.toList(), read.hmacSecret.toList())
    }

    @Test
    fun deleteFreesTheSlotAndKeepsTheOthers() {
        var blob = FidoStoreBlob.empty()
        blob = blob.withCredential(record(0, "one.example"))!!
        blob = blob.withCredential(record(1, "two.example"))!!
        val reduced = FidoStoreBlob.parse(blob.withoutSlot(0).toBytes())!!
        assertEquals(listOf("two.example"), reduced.credentials().map { it.rpId })
        assertNull(reduced.credentialAt(0))
        assertEquals(FidoStoreBlob.MAX_CREDS - 1, reduced.freeSlots())
    }

    @Test
    fun renameReplacesOnlyTheNameFields() {
        val blob = FidoStoreBlob.empty().withCredential(record(0, "example.com"))!!
        val renamed = FidoStoreBlob.parse(
            blob.withRenamedSlot(0, "bob@example.com", "Bob").toBytes()
        )!!.credentialAt(0)!!
        assertEquals("bob@example.com", renamed.userName)
        assertEquals("Bob", renamed.userDisplay)
        assertEquals("example.com", renamed.rpId)
        assertEquals(blob.credentialAt(0)!!.credId.toList(), renamed.credId.toList())
    }

    @Test
    fun aTooLongNameIsTruncatedWithoutBreakingAMultiByteCharacter() {
        // 63 usable bytes per name field, and "é" takes two of them.
        val long = "é".repeat(40)
        val stored = FidoStoreBlob.parse(
            FidoStoreBlob.empty().withCredential(record(0, "example.com", name = long))!!.toBytes()
        )!!.credentialAt(0)!!
        assertEquals(31, stored.userName.length)
        assertTrue(long.startsWith(stored.userName))
    }

    @Test
    fun theStoreRefusesToGrowPastItsSlotCount() {
        var blob: FidoStoreBlob? = FidoStoreBlob.empty()
        repeat(FidoStoreBlob.MAX_CREDS) { slot ->
            blob = blob!!.withCredential(record(slot, "site$slot.example"))
            assertNotNull(blob)
        }
        assertEquals(0, blob!!.freeSlots())
        assertNull(blob!!.withCredential(record(0, "overflow.example")))
    }

    @Test
    fun aCorruptCrcIsRejected() {
        val bytes = FidoStoreBlob.empty().withCredential(record(0, "example.com"))!!.toBytes()
        bytes[FidoStoreBlob.HEADER_SIZE + 100] = 'x'.code.toByte()
        assertNull(FidoStoreBlob.parse(bytes))
        assertNotNull(FidoStoreBlob.parse(bytes, ignoreCrc = true))
    }

    @Test
    fun aVersionOneBlobIsUpgradedWithZeroedSecrets() {
        // Hand-built v1 layout: 84-byte header + 32 * 452-byte slots, one
        // credential in slot 0, no hmac-secret field.
        val v1 = ByteArray(FidoStoreBlob.SIZE_V1)
        v1[0] = 0x46; v1[1] = 0x46; v1[2] = 0x42; v1[3] = 0x41 // 0x41424646 LE
        writeIntLe(v1, 4, 1) // version 1
        val slot0 = FidoStoreBlob.HEADER_SIZE
        v1[slot0] = 1 // in_use
        v1[slot0 + 1] = 1 // resident
        v1[slot0 + 2] = 4
        "v1.example.com".toByteArray().copyInto(v1, slot0 + 100)
        val crc = CRC32().apply { update(v1, 12, v1.size - 12) }.value.toInt()
        writeIntLe(v1, 8, crc)

        val parsed = FidoStoreBlob.parse(v1)!!
        val cred = parsed.credentialAt(0)!!
        assertEquals("v1.example.com", cred.rpId)
        assertTrue(cred.hmacSecret.all { it == 0.toByte() })

        // Resealing writes the v2 layout the driver expects.
        val resealed = parsed.toBytes()
        assertEquals(FidoStoreBlob.SIZE, resealed.size)
        assertEquals(2, readIntLe(resealed, 4))
        assertNotNull(FidoStoreBlob.parse(resealed))
    }

    @Test
    fun aWrongStoreVersionIsRefused() {
        val bytes = FidoStoreBlob.empty().toBytes()
        writeIntLe(bytes, 4, 3)
        assertNull(FidoStoreBlob.parse(bytes))
    }
}
