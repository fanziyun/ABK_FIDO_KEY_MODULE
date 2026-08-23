package com.abk.extension.fido

import android.util.Base64
import android.util.Log

private const val STORE_PATH = "/metadata/abk_fido_store.bin"
private const val TAG = "AbkFidoStore"

/** Outcome of an operation that has to survive into the kernel to count. */
internal sealed class StoreEditResult {
    object Success : StoreEditResult()
    class Failure(val message: String) : StoreEditResult()
}

/**
 * Everything the UI does to the key store: read it, edit it, and make the
 * driver adopt the result.
 *
 * The driver owns the live store, so an edit is a three-step move — rewrite
 * `/metadata/abk_fido_store.bin`, poke `restore_metadata`, then confirm the
 * store generation advanced. Without the last step a rejected blob (bad CRC,
 * for instance) would look like a success while the key kept its old contents.
 */
internal object FidoStoreManager {

    /** Read the persisted store. Returns null when root or the file is missing. */
    fun read(): FidoStoreBlob? {
        val result = RootShell.readFileBase64(STORE_PATH)
        if (!result.success) {
            Log.w(TAG, "read $STORE_PATH failed exit=${result.exitCode} out=${result.stdout}")
            return null
        }
        val encoded = result.stdout.trim()
        if (encoded.isEmpty()) return FidoStoreBlob.empty()
        val bytes = runCatching { Base64.decode(encoded, Base64.DEFAULT) }.getOrNull() ?: return null
        if (bytes.isEmpty()) return FidoStoreBlob.empty()
        return FidoStoreBlob.parse(bytes)
    }

    fun delete(slot: Int): StoreEditResult {
        val store = read() ?: return StoreEditResult.Failure("cannot read the FIDO store")
        val record = store.credentialAt(slot)
            ?: return StoreEditResult.Failure("that key is no longer in the store")
        return commit(store.withoutSlot(slot)).also {
            if (it is StoreEditResult.Success) {
                Log.i(TAG, "deleted slot=$slot rp=${record.rpId}")
            }
        }
    }

    fun rename(slot: Int, userName: String, userDisplay: String): StoreEditResult {
        val store = read() ?: return StoreEditResult.Failure("cannot read the FIDO store")
        store.credentialAt(slot)
            ?: return StoreEditResult.Failure("that key is no longer in the store")
        return commit(store.withRenamedSlot(slot, userName, userDisplay))
    }

    /**
     * Add credentials from an archive. Anything whose credential id is already
     * present is skipped rather than duplicated, because the driver matches
     * assertions by credential id and two identical ids would be ambiguous.
     */
    fun import(records: List<FidoCredentialRecord>): ImportOutcome {
        val store = read() ?: return ImportOutcome(
            result = StoreEditResult.Failure("cannot read the FIDO store"),
            imported = 0,
            skipped = 0,
        )
        val existing = store.credentials().map { it.credIdHex }.toMutableSet()
        var next = store
        var imported = 0
        var skipped = 0
        for (record in records) {
            if (!existing.add(record.credIdHex)) {
                skipped++
                continue
            }
            val updated = next.withCredential(record)
            if (updated == null) {
                return ImportOutcome(
                    result = StoreEditResult.Failure(
                        "the store is full at ${FidoStoreBlob.MAX_CREDS} keys; $imported imported before that"
                    ),
                    imported = imported,
                    skipped = skipped,
                )
            }
            next = updated
            imported++
        }
        if (imported == 0) {
            return ImportOutcome(StoreEditResult.Success, imported = 0, skipped = skipped)
        }
        return ImportOutcome(commit(next), imported = imported, skipped = skipped)
    }

    class ImportOutcome(val result: StoreEditResult, val imported: Int, val skipped: Int)

    /**
     * Write the blob and wait for the driver to pick it up. `restore_metadata`
     * bumps `store_generation` on success, which is the only unambiguous signal
     * that the new contents are live.
     */
    private fun commit(store: FidoStoreBlob): StoreEditResult {
        val bytes = store.toBytes()
        val generationBefore = FidoKernelBridge.readStoreGeneration()
            ?: return StoreEditResult.Failure("the abk_fido_key driver is not loaded")

        val write = RootShell.writeFileBase64(STORE_PATH, Base64.encodeToString(bytes, Base64.NO_WRAP))
        if (!write.success) {
            return StoreEditResult.Failure("writing $STORE_PATH failed: ${write.stdout.trim()}")
        }

        val trigger = FidoKernelBridge.restoreMetadata()
        if (!trigger.success) {
            return StoreEditResult.Failure("restore_metadata rejected the store: ${trigger.stdout.trim()}")
        }

        val expected = store.credentials().size
        repeat(RESTORE_ATTEMPTS) {
            val generation = FidoKernelBridge.readStoreGeneration()
            val count = FidoKernelBridge.readCredentialCount()
            if (generation != null && generation > generationBefore && count != null && count == expected) {
                return StoreEditResult.Success
            }
            Thread.sleep(RESTORE_DELAY_MS)
        }
        val error = FidoKernelBridge.readLastError().ifBlank { FidoKernelBridge.readLastTrace() }
        return StoreEditResult.Failure(
            "the driver did not adopt the edited store" + if (error.isBlank()) "" else ": $error"
        )
    }

    private const val RESTORE_ATTEMPTS = 20
    private const val RESTORE_DELAY_MS = 200L
}
