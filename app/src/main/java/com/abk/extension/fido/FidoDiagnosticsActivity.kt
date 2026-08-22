package com.abk.extension.fido

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.abk.extension.fido.diagnostics.PhoneDiagnosticRunner
import com.abk.extension.fido.diagnostics.TabletFidoTester
import com.abk.extension.fido.diagnostics.UsbFidoCandidate
import com.abk.extension.fido.diagnostics.findUsbFidoCandidates
import java.util.concurrent.Executors

class FidoDiagnosticsActivity : AppCompatActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var status: TextView
    private lateinit var reportView: TextView
    private lateinit var roleSpinner: Spinner
    private var latestReport = ""
    private var pendingUsbDevice: UsbDevice? = null
    private val usbPermissionReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != ACTION_USB_PERMISSION) return
            val device = if (Build.VERSION.SDK_INT >= 33) {
                intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
            } else {
                @Suppress("DEPRECATION") intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
            }
            if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false) && device != null) {
                runTablet(device)
            } else {
                showMessage("USB 权限被拒绝")
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        registerUsbReceiver()
        setContentView(buildUi())
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(usbPermissionReceiver) }
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun buildUi(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 28, 32, 24)
        }
        val title = TextView(this).apply {
            text = "ABK FIDO 连接测试"
            textSize = 24f
            setTextColor(0xff202124.toInt())
        }
        root.addView(title, LinearLayout.LayoutParams(-1, -2))
        root.addView(TextView(this).apply {
            text = "手机运行 FIDO，平板运行 USB 测试。这个工具不会读取私钥或导出凭据。"
            textSize = 14f
            setPadding(0, 8, 0, 18)
        }, LinearLayout.LayoutParams(-1, -2))

        roleSpinner = Spinner(this).apply {
            adapter = android.widget.ArrayAdapter(
                this@FidoDiagnosticsActivity,
                android.R.layout.simple_spinner_dropdown_item,
                arrayOf("自动检测", "手机端测试", "平板端测试")
            )
        }
        root.addView(roleSpinner, LinearLayout.LayoutParams(-1, -2))

        val run = Button(this).apply {
            text = "开始测试"
            setOnClickListener { startTest() }
        }
        root.addView(run, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 16 })

        status = TextView(this).apply {
            text = "准备就绪"
            textSize = 16f
            setPadding(0, 18, 0, 12)
        }
        root.addView(status, LinearLayout.LayoutParams(-1, -2))

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        actions.addView(Button(this).apply {
            text = "保存报告"
            setOnClickListener { saveReport() }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        actions.addView(Button(this).apply {
            text = "分享报告"
            setOnClickListener { shareReport() }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        root.addView(actions, LinearLayout.LayoutParams(-1, -2))

        reportView = TextView(this).apply {
            textSize = 12f
            typeface = android.graphics.Typeface.MONOSPACE
            movementMethod = ScrollingMovementMethod()
            setTextIsSelectable(true)
            setPadding(12, 12, 12, 12)
            setBackgroundColor(0xfff1f3f4.toInt())
        }
        root.addView(ScrollView(this).apply {
            addView(reportView)
        }, LinearLayout.LayoutParams(-1, 0, 1f).apply { topMargin = 12 })
        return root
    }

    private fun startTest() {
        val selected = roleSpinner.selectedItemPosition
        if (selected == 1 || (selected == 0 && RootShell.isRootAvailable())) {
            runPhone()
        } else {
            runTabletSelection()
        }
    }

    private fun runPhone() {
        status.text = "手机测试进行中..."
        executor.execute {
            val result = PhoneDiagnosticRunner.run(this) { stage -> runOnUiThread { status.text = stage } }
            finishReport(result.report, result.passed)
        }
    }

    private fun runTabletSelection() {
        val manager = getSystemService(UsbManager::class.java)
        val candidates = manager.deviceList.values.flatMap { findUsbFidoCandidates(it) }
        if (candidates.isEmpty()) {
            showMessage("没有找到 USB HID 接口。请让手机连接到平板并确认 OTG/USB Host 已开启。")
            return
        }
        val candidate = candidates.first()
        pendingUsbDevice = candidate.device
        if (!manager.hasPermission(candidate.device)) {
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
            manager.requestPermission(
                candidate.device,
                PendingIntent.getBroadcast(this, 1, Intent(ACTION_USB_PERMISSION), flags)
            )
        } else {
            runTablet(candidate.device)
        }
    }

    private fun runTablet(device: UsbDevice) {
        val manager = getSystemService(UsbManager::class.java)
        val candidates = findUsbFidoCandidates(device)
        val candidate = candidates.firstOrNull()
        if (candidate == null) {
            showMessage("找到 USB 设备，但没有 HID IN/OUT 中断端点")
            return
        }
        status.text = "平板测试进行中..."
        executor.execute {
            val connection = manager.openDevice(device)
            if (connection == null) {
                finishReport("USB openDevice 失败\n", false)
                return@execute
            }
            val result = TabletFidoTester(connection, candidate).run(false) { stage ->
                runOnUiThread { status.text = stage }
            }
            connection.close()
            finishReport(result.report, result.passed)
        }
    }

    private fun finishReport(report: String, passed: Boolean) {
        latestReport = report
        runOnUiThread {
            status.text = if (passed) "测试通过" else "测试失败，请保存报告"
            reportView.text = report
        }
    }

    private fun saveReport() {
        if (latestReport.isBlank()) {
            showMessage("请先开始测试")
            return
        }
        executor.execute {
            val result = PhoneDiagnosticRunner.saveToDownloads(latestReport, "abk_fido_diagnostic")
            runOnUiThread {
                if (result.success) showMessage("报告已保存到 Download")
                else shareReport()
            }
        }
    }

    private fun shareReport() {
        if (latestReport.isBlank()) {
            showMessage("请先开始测试")
            return
        }
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, latestReport)
            putExtra(Intent.EXTRA_SUBJECT, "ABK FIDO diagnostic report")
        }, "分享诊断报告"))
    }

    private fun registerUsbReceiver() {
        val filter = IntentFilter(ACTION_USB_PERMISSION)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(usbPermissionReceiver, filter, RECEIVER_NOT_EXPORTED)
        else @Suppress("DEPRECATION") registerReceiver(usbPermissionReceiver, filter)
    }

    private fun showMessage(message: String) {
        runOnUiThread { Toast.makeText(this, message, Toast.LENGTH_LONG).show() }
    }

    companion object {
        private const val ACTION_USB_PERMISSION = "com.abk.extension.fido.USB_PERMISSION"
    }
}
