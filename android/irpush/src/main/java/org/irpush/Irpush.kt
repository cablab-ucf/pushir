package org.irpush

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import java.io.File
import kotlin.concurrent.thread

private const val ATTACH = "org.irpush.ATTACH"
private const val HELLO = 1
private const val ID = 2
private const val PUSH = 3
private val main = Handler(Looper.getMainLooper())

/** The app's native library links the irpush crate with feature `jni`. */
internal object Native {
    @JvmStatic external fun start(path: String): String
    @JvmStatic external fun next(): ByteArray
}

/** The group's app installed first: the same answer in every app. */
internal fun owner(c: Context): ComponentName? {
    val pm = c.packageManager
    return pm.queryIntentServices(Intent(ATTACH), 0).map { it.serviceInfo }
        .filter { pm.checkSignatures(c.packageName, it.packageName) == PackageManager.SIGNATURE_MATCH }
        .minWithOrNull(compareBy({ pm.getPackageInfo(it.packageName, 0).firstInstallTime }, { it.packageName }))
        ?.let { ComponentName(it.packageName, it.name) }
}

private fun ownerStart(c: Context) {
    if (owner(c)?.packageName == c.packageName) c.startForegroundService(Intent(c, Broker::class.java))
}

/**
 * One connection per phone for every app of the group. Call [start] in
 * `Application.onCreate` with the app's [slot] (random, kept): frames sent
 * to it arrive in [onPush], sealed as the sender sealed them.
 */
object Irpush {
    private lateinit var app: Context
    private lateinit var slot: ByteArray
    private var onId: (String) -> Unit = {}
    private var onPush: (ByteArray) -> Unit = {}
    private var bound = false

    private val me = Messenger(Handler(Looper.getMainLooper()) { m ->
        runCatching {
            when (m.what) {
                ID -> m.data.getString("id")?.let(onId)
                PUSH -> m.data.getByteArray("d")?.let(onPush)
            }
        }
        true
    })

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(n: ComponentName, b: IBinder) {
            val m = Message.obtain(null, HELLO)
            m.data = Bundle().apply { putByteArray("slot", slot); putString("pkg", app.packageName) }
            m.replyTo = me
            runCatching { Messenger(b).send(m) }
        }
        override fun onServiceDisconnected(n: ComponentName) = Unit
        override fun onBindingDied(n: ComponentName) = rebind()
        override fun onNullBinding(n: ComponentName) = rebind()
    }

    /** [lib]: the app's native library. [onId]: the mailbox id, for senders. */
    fun start(c: Context, lib: String, slot: ByteArray, onId: (String) -> Unit, onPush: (ByteArray) -> Unit) {
        System.loadLibrary(lib)
        app = c.applicationContext
        this.slot = slot
        this.onId = onId
        this.onPush = onPush
        ownerStart(app)
        bind()
    }

    private fun bind() = main.post {
        val o = owner(app) ?: return@post
        if (!bound) bound = app.bindService(Intent(ATTACH).setComponent(o), conn, Context.BIND_AUTO_CREATE)
    }

    private fun rebind() {
        runCatching { app.unbindService(conn) }
        bound = false
        ownerStart(app)
        main.postDelayed({ bind() }, 1000)
    }
}

/** The owner's: holds the mailbox and hands each frame to its slot's app,
 *  unopened. An app not attached is woken; 64 frames wait for it. */
class Broker : Service() {
    private val apps = HashMap<String, Messenger>()
    private val held = HashMap<String, ArrayDeque<ByteArray>>()
    private var id = ""

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private val pkgs get() = getSharedPreferences("irpush", MODE_PRIVATE)

    private val inbox = Messenger(Handler(Looper.getMainLooper()) { m ->
        val slot = m.data?.getByteArray("slot")?.hex()
        val pkg = m.data?.getString("pkg")
        val to = m.replyTo
        if (slot != null && pkg != null && to != null) {
            apps[slot] = to
            pkgs.edit().putString(slot, pkg).apply()
            tell(to, ID, Bundle().apply { putString("id", id) })
            held.remove(slot)?.forEach { deliver(slot, it) }
        }
        true
    })

    private fun tell(to: Messenger, what: Int, b: Bundle) =
        runCatching { to.send(Message.obtain(null, what).apply { data = b }) }.isSuccess

    private fun deliver(slot: String, d: ByteArray) {
        val to = apps[slot]
        if (to != null && tell(to, PUSH, Bundle().apply { putByteArray("d", d) })) return
        apps.remove(slot)
        held.getOrPut(slot) { ArrayDeque() }.apply { addLast(d); while (size > 64) removeFirst() }
        pkgs.getString(slot, null)?.let { sendBroadcast(Intent("org.irpush.WAKE").setPackage(it)) }
    }

    override fun onCreate() {
        super.onCreate()
        id = Native.start(File(filesDir, "irpush.key").path)
        thread(isDaemon = true) {
            while (true) {
                val f = Native.next()
                if (f.size >= 16) main.post { deliver(f.copyOf(16).hex(), f.copyOfRange(16, f.size)) }
            }
        }
    }

    override fun onStartCommand(i: Intent?, flags: Int, startId: Int): Int {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("irpush", "Push", NotificationManager.IMPORTANCE_MIN))
        val n = Notification.Builder(this, "irpush").setContentTitle("Ready for pushes")
            .setSmallIcon(android.R.drawable.stat_notify_sync).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
        else startForeground(1, n)
        return START_STICKY
    }

    override fun onBind(i: Intent?): IBinder = inbox.binder
}

/** A frame waits for this app: starting its process is enough. */
class Wake : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) = Unit
}

class Boot : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) = ownerStart(c)
}
