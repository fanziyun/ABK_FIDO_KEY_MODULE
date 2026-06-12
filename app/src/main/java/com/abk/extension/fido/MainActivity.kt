package com.abk.extension.fido

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.concurrent.thread

class MainActivity : Activity() {
    private lateinit var statusView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        statusView = TextView(this).apply {
            text = getString(R.string.status_syncing)
            textSize = 16f
        }

        val syncButton = Button(this).apply {
            text = getString(R.string.sync_now)
            setOnClickListener { runSync("launcher") }
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(48, 64, 48, 64)
            addView(
                statusView,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            )
            addView(
                syncButton,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = 32
                }
            )
        }

        setContentView(layout)
        runSync("launcher")
    }

    private fun runSync(reason: String) {
        statusView.text = getString(R.string.status_syncing)
        thread(name = "abk-fido-sync") {
            val result = MetadataSyncCoordinator(applicationContext).syncNow(reason)
            runOnUiThread {
                statusView.text = result.userMessage(this)
            }
        }
    }
}
