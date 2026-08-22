package com.abk.extension.fido

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import android.graphics.Color
import android.view.Gravity

class PairingCodeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val code = RootShell.readTextFile("/metadata/abk_fido_pairing_code").stdout.trim()
        val view = TextView(this).apply {
            text = "ABK FIDO\n\n配对码: $code\n\n请在电脑端输入此配对码"
            textSize = 22f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }
        setContentView(view)
    }
}
