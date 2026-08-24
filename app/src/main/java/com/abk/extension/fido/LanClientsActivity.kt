package com.abk.extension.fido

import android.os.Bundle
import android.text.format.DateUtils
import android.view.View
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.PopupMenu
import androidx.core.view.isVisible
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.color.DynamicColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch

/**
 * The computers allowed to use the key over the LAN.
 *
 * The pairing code only protects the transport, so this is where the user says
 * which machines may actually talk to the key. Everything here is local state in
 * [LanClientRegistry]; the relay reads it on the next connection, and closing a
 * running session is not needed because each session re-checks on hello.
 */
class LanClientsActivity : AppCompatActivity() {

    private lateinit var settings: FidoSettings
    private lateinit var registry: LanClientRegistry
    private lateinit var autoSwitch: MaterialSwitch
    private lateinit var container: LinearLayout
    private lateinit var empty: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DynamicColors.applyToActivityIfAvailable(this)
        setContentView(R.layout.activity_lan_clients)
        settings = FidoSettings.of(this)
        registry = LanClientRegistry.of(this)

        findViewById<MaterialToolbar>(R.id.toolbar).setNavigationOnClickListener { finish() }
        autoSwitch = findViewById(R.id.autoAuthorizeSwitch)
        container = findViewById(R.id.clientsContainer)
        empty = findViewById(R.id.clientsEmpty)
        findViewById<View>(R.id.autoAuthorizeRow).setOnClickListener {
            settings.autoAuthorizeNewClients = !settings.autoAuthorizeNewClients
            render()
        }
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun render() {
        autoSwitch.isChecked = settings.autoAuthorizeNewClients
        val records = registry.list()
        container.removeAllViews()
        empty.isVisible = records.isEmpty()
        records.forEach(::addClientRow)
    }

    private fun addClientRow(record: LanClientRecord) {
        val row = layoutInflater.inflate(R.layout.item_lan_client, container, false)
        row.findViewById<TextView>(R.id.clientName).text = record.displayName(this)
        row.findViewById<TextView>(R.id.clientStatus).text = getString(statusLabel(record.status))
        val lastSeen = if (record.lastSeen <= 0L) {
            ""
        } else {
            getString(R.string.lan_last_seen, DateUtils.getRelativeTimeSpanString(this, record.lastSeen))
        }
        val detail = row.findViewById<TextView>(R.id.clientDetail)
        detail.text = getString(R.string.lan_client_detail, record.address, lastSeen)
        val overflow = row.findViewById<ImageButton>(R.id.clientOverflow)
        overflow.setOnClickListener { showMenu(overflow, record) }
        row.setOnClickListener { showMenu(overflow, record) }
        container.addView(row)
    }

    private fun statusLabel(status: LanClientStatus): Int = when (status) {
        LanClientStatus.PENDING -> R.string.lan_status_pending
        LanClientStatus.AUTHORIZED -> R.string.lan_status_authorized
        LanClientStatus.BLOCKED -> R.string.lan_status_blocked
    }

    private fun showMenu(anchor: View, record: LanClientRecord) {
        val menu = PopupMenu(this, anchor)
        menu.inflate(R.menu.lan_client_row)
        // Only offer the moves that change something for this row.
        menu.menu.findItem(R.id.menu_client_authorize).isVisible =
            record.status != LanClientStatus.AUTHORIZED
        menu.menu.findItem(R.id.menu_client_revoke).isVisible =
            record.status == LanClientStatus.AUTHORIZED
        menu.menu.findItem(R.id.menu_client_block).isVisible =
            record.status != LanClientStatus.BLOCKED
        menu.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.menu_client_authorize -> setStatus(record, LanClientStatus.AUTHORIZED)
                R.id.menu_client_revoke -> setStatus(record, LanClientStatus.PENDING)
                R.id.menu_client_block -> setStatus(record, LanClientStatus.BLOCKED)
                R.id.menu_client_forget -> confirmForget(record)
                else -> return@setOnMenuItemClickListener false
            }
            true
        }
        menu.show()
    }

    private fun setStatus(record: LanClientRecord, status: LanClientStatus) {
        registry.setStatus(record.id, status)
        render()
    }

    /**
     * Forgetting drops the record entirely, so the same computer comes back as
     * a new pending entry. For an address-only client that is also the only way
     * to undo a decision after its address changed.
     */
    private fun confirmForget(record: LanClientRecord) {
        MaterialAlertDialogBuilder(this)
            .setTitle(record.displayName(this))
            .setMessage(
                if (record.anonymous) getString(R.string.lan_anonymous_note) else record.address
            )
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.lan_menu_forget) { _, _ ->
                registry.remove(record.id)
                render()
            }
            .show()
    }
}
