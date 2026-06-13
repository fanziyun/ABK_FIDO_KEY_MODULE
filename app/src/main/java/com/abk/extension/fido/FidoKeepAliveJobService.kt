package com.abk.extension.fido

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build

class FidoKeepAliveJobService : JobService() {
    override fun onStartJob(params: JobParameters?): Boolean {
        val intent = Intent(this, FidoSyncService::class.java).apply {
            action = FidoSyncService.ACTION_SYNC_NOW
            putExtra(FidoSyncService.EXTRA_REASON, "job_keepalive")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        jobFinished(params, false)
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean = false

    companion object {
        private const val JOB_ID = 0xA8F1D0

        fun schedule(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            val component = ComponentName(context, FidoKeepAliveJobService::class.java)
            val info = JobInfo.Builder(JOB_ID, component)
                .setPersisted(true)
                .setPeriodic(15 * 60 * 1000L)
                .build()
            scheduler.schedule(info)
        }
    }
}
