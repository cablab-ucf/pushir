package org.pushir

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.SystemClock
import java.io.File
import kotlin.concurrent.thread

private const val ATTACH = "org.pushir.ATTACH"
private const val HELLO = 1
private const val ID = 2
private const val PUSH = 3
private val main = Handler(Looper.getMainLooper())

/** The app's native library links the pushir crate with feature `jni`. */
internal object Native {
    @JvmStatic external fun start(path: String): String
    @JvmStatic external fun next(): ByteArray
    @JvmStatic external fun route(secret: ByteArray): ByteArray
    @JvmStatic external fun hears(route: ByteArray, frame: ByteArray): Boolean
    @JvmStatic external fun open(secret: ByteArray, frame: ByteArray): ByteArray?
    @JvmStatic external fun kick(): Long
}

private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
private fun String.unhex() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/** The group's app installed first: the same answer in every app. */
internal fun owner(c: Context): ComponentName? {
    val pm = c.packageManager
    return pm.queryIntentServices(Intent(ATTACH), 0).map { it.serviceInfo }
        .filter { pm.checkSignatures(c.packageName, it.packageName) == PackageManager.SIGNATURE_MATCH }
        .minWithOrNull(compareBy({ pm.getPackageInfo(it.packageName, 0).firstInstallTime }, { it.packageName }))
        ?.let { ComponentName(it.packageName, it.name) }
}

/** Not from the background on Android 12+: then the system's own restart of the service stands. */
private fun ownerStart(c: Context) {
    if (owner(c)?.packageName == c.packageName) runCatching { c.startForegroundService(Intent(c, Broker::class.java)) }
}

/** Ping the relay now, and wake for the next ping when it says: timers sleep with the phone, alarms do not. */
private fun beat(c: Context) {
    val next = runCatching { Native.kick() }.getOrDefault(60)
    val tick = PendingIntent.getBroadcast(c, 0, Intent(c, Beat::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    c.getSystemService(AlarmManager::class.java)?.setAndAllowWhileIdle(
        AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + next * 1000, tick)
}

/**
 * One connection per phone for every app of the group. Call [start] in
 * `Application.onCreate` with the app's lane [secret] (32 random bytes,
 * kept, given to its senders alone): what they send arrives in [onPush],
 * opened. An empty one says sync: a sender's bare wake, or the connection
 * back from a gap in which frames may have been missed.
 */
object Pushir {
    private lateinit var app: Context
    private lateinit var secret: ByteArray
    private var onId: (String) -> Unit = {}
    private var onPush: (ByteArray) -> Unit = {}
    private var bound = false

    private val me = Messenger(Handler(Looper.getMainLooper()) { m ->
        runCatching {
            when (m.what) {
                ID -> m.data.getString("id")?.let(onId)
                PUSH -> m.data.getByteArray("d")?.let { if (it.isEmpty()) it else Native.open(secret, it) }?.let(onPush)
            }
        }
        true
    })

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(n: ComponentName, b: IBinder) {
            val m = Message.obtain(null, HELLO)
            m.data = Bundle().apply { putByteArray("route", Native.route(secret)) }
            m.replyTo = me
            runCatching { Messenger(b).send(m) }
        }
        override fun onServiceDisconnected(n: ComponentName) = Unit
        override fun onBindingDied(n: ComponentName) = rebind()
        override fun onNullBinding(n: ComponentName) = rebind()
    }

    /** [lib]: the app's native library. [onId]: the mailbox id, for the lane the app gives its senders. */
    fun start(c: Context, lib: String, secret: ByteArray, onId: (String) -> Unit, onPush: (ByteArray) -> Unit) {
        System.loadLibrary(lib)
        app = c.applicationContext
        this.secret = secret
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

/** The owner's: holds the mailbox and hands each frame, unopened, to the
 *  app whose lane hears it. It knows a lane by its route key alone, which
 *  opens nothing. An app not running is woken; 64 frames wait in all. */
class Broker : Service() {
    private val apps = HashMap<String, Messenger>()
    private val held = ArrayDeque<ByteArray>()
    private var id = ""

    /** Each lane's route key (hex) and its app, kept to wake an app not running. */
    private val lanes get() = getSharedPreferences("pushir", MODE_PRIVATE)

    private val inbox = Messenger(Handler(Looper.getMainLooper()) { m ->
        val route = m.data?.getByteArray("route")
        val pkg = packageManager.getPackagesForUid(m.sendingUid)?.firstOrNull()
        val to = m.replyTo
        if (m.what == HELLO && route?.size == 32 && pkg != null && to != null) {
            // An app has one lane: its newest.
            val e = lanes.edit()
            lanes.all.filterValues { it == pkg }.keys.forEach { apps.remove(it); e.remove(it) }
            e.putString(route.hex(), pkg).apply()
            apps[route.hex()] = to
            tell(to, ID, Bundle().apply { putString("id", id) })
            held.removeAll { Native.hears(route, it) && tell(to, PUSH, Bundle().apply { putByteArray("d", it) }) }
        }
        true
    })

    private fun tell(to: Messenger, what: Int, b: Bundle) =
        runCatching { to.send(Message.obtain(null, what).apply { data = b }) }.isSuccess

    private fun deliver(f: ByteArray) {
        val d = Bundle().apply { putByteArray("d", f) }
        // Back from a gap: every app syncs.
        if (f.isEmpty()) return apps.values.forEach { tell(it, PUSH, d) }
        val lane = lanes.all.entries.firstOrNull { Native.hears(it.key.unhex(), f) }
        if (lane != null && apps[lane.key]?.let { tell(it, PUSH, d) } == true) return
        lane?.let { apps.remove(it.key) }
        held.addLast(f)
        while (held.size > 64) held.removeFirst()
        (lane?.value as? String)?.let { sendBroadcast(Intent("org.pushir.WAKE").setPackage(it)) }
    }

    override fun onCreate() {
        super.onCreate()
        id = Native.start(File(filesDir, "pushir.key").path)
        thread(isDaemon = true) {
            while (true) {
                val f = Native.next()
                main.post { deliver(f) }
            }
        }
        // Set the alarm; and at each network that comes up, reconnect at once.
        thread { beat(this) }
        getSystemService(ConnectivityManager::class.java)?.registerDefaultNetworkCallback(
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(n: Network) { thread { beat(this@Broker) } }
            })
    }

    override fun onStartCommand(i: Intent?, flags: Int, startId: Int): Int {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("pushir", "Push", NotificationManager.IMPORTANCE_MIN))
        val n = Notification.Builder(this, "pushir").setContentTitle("Ready for pushes")
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

/** The alarm: the phone stays awake for the ping's answer, no longer. */
class Beat : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        ownerStart(c)
        val done = goAsync()
        thread { beat(c); done.finish() }
    }
}
