package com.abk.extension.fido

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.dialog.MaterialAlertDialogBuilder

class PairingCodeActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val code = RootShell.readTextFile("/metadata/abk_fido_pairing_code").stdout.trim()
        val codeView = TextView(this).apply {
            text = code.ifBlank { "Unavailable" }
            textSize = 32f
            typeface = Typeface.MONOSPACE
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER
            letterSpacing = 0.16f
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 4, 24, 8)
            addView(TextView(this@PairingCodeActivity).apply {
                text = "Enter this code in the desktop agent to pair this phone."
                textSize = 15f
                setPadding(0, 0, 0, 20)
            })
            addView(codeView)
        }

        MaterialAlertDialogBuilder(this)
            .setTitle("Pair ABK FIDO")
            .setView(content)
            .setNegativeButton("Close") { _, _ -> finish() }
            .setPositiveButton("Copy code") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("ABK FIDO pairing code", code))
                Toast.makeText(this, "Pairing code copied", Toast.LENGTH_SHORT).show()
            }
            .setOnDismissListener { finish() }
            .show()
    }
}
