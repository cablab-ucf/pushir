package org.pushir

import android.Manifest.permission.POST_NOTIFICATIONS
import android.app.Activity
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
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import java.io.File
import kotlin.concurrent.thread

private val main = Handler(Looper.getMainLooper())

/** This app's own mailbox key: never another app's (an older pushir shared
 *  one app's `pushir.key` with the others; that one is left unused). */
private const val KEY = "pushir.mailbox"

/** How long a frame keeps the phone awake for its app. */
private const val AWAKE = 30_000L

/** The app's native library links the pushir crate with feature `jni`. */
internal object Native {
    @JvmStatic external fun start(path: String): String
    @JvmStatic external fun stop()
    @JvmStatic external fun next(): ByteArray
    @JvmStatic external fun open(secret: ByteArray, frame: ByteArray): ByteArray?
    @JvmStatic external fun kick(): Long
    @JvmStatic external fun moved(net: String)
}

/** Ping the relay now, and wake for the next ping when it says: timers sleep with the phone, alarms do not. */
private fun beat(c: Context) {
    val next = runCatching { Native.kick() }.getOrDefault(60)
    val tick = PendingIntent.getBroadcast(c, 0, Intent(c, Beat::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    c.getSystemService(AlarmManager::class.java)?.setAndAllowWhileIdle(
        AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + next * 1000, tick)
}

/** This app's mailbox service started, or stopped. Not started from the
 *  background on Android 12+ unless the app is exempt from battery
 *  optimisation: then the binding in [Pushir.start] keeps it. */
private fun broker(c: Context, on: Boolean) = runCatching {
    val i = Intent(c, Broker::class.java)
    if (on) c.startForegroundService(i) else c.stopService(i)
}.onFailure { Pushir.refused = "Android refused to start it (${it.javaClass.simpleName})" }

/**
 * The app's own mailbox on a relay, held by its own foreground service:
 * nothing of it depends on another app. Call [start] in
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
    /** Started, not stopped: this app listens (an alarm or boot of a
     *  process whose app does not listen starts nothing). */
    @Volatile internal var on = false
    /** Why the mailbox is not held in the foreground, or null while it is. */
    @Volatile internal var refused: String? = "Android has not started it"

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(n: ComponentName, b: IBinder) = Unit
        override fun onServiceDisconnected(n: ComponentName) = Unit
    }

    /** [lib]: the app's native library. [onId]: the mailbox id, for the lane the app gives its senders. */
    fun start(c: Context, lib: String, secret: ByteArray, onId: (String) -> Unit, onPush: (ByteArray) -> Unit) {
        System.loadLibrary(lib)
        app = c.applicationContext
        this.secret = secret
        this.onId = onId
        this.onPush = onPush
        on = true
        broker(app, true)
        // Bound too: the service is made even where Android refuses a
        // foreground start from the background.
        if (!bound) bound = runCatching {
            app.bindService(Intent(app, Broker::class.java), conn, Context.BIND_AUTO_CREATE)
        }.getOrDefault(false)
    }

    /** Start the service in the foreground now, from an activity in sight
     *  (where Android always allows it): a start refused in the background,
     *  at boot or from an alarm, is made good the moment the app is opened. */
    fun hold(c: Context) {
        if (on) broker(c.applicationContext, true)
    }

    /** Why this app's pushes cannot reach a sleeping phone now (its service
     *  not held in the foreground, so Android freezes it), or null if they can. */
    fun held(): String? = refused

    /** This app no longer listens: its mailbox let go, its service gone. [start] listens again. */
    fun stop(c: Context) {
        on = false
        if (bound) runCatching { app.unbindService(conn) }
        bound = false
        broker(c.applicationContext, false)
    }

    internal fun id(id: String) = main.post { runCatching { onId(id) } }

    /** A frame from the mailbox, opened with this app's secret (empty: sync). */
    internal fun frame(f: ByteArray) {
        if (!::secret.isInitialized) return
        val m = if (f.isEmpty()) f else Native.open(secret, f) ?: return
        awake()
        main.post { runCatching { onPush(m) } }
    }

    private var lock: PowerManager.WakeLock? = null

    /** Data wakes a sleeping phone for a moment only: awake [AWAKE] ms for
     *  [onPush] to show what came, and for the relay's ping after it (else
     *  it drops the connection). Only for a frame this app opens: a stranger
     *  keeps no phone awake. */
    private fun awake() = runCatching {
        val l = lock ?: app.getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "pushir:frame")
            .apply { setReferenceCounted(false) }.also { lock = it }
        l.acquire(AWAKE)
    }

    /**
     * From an activity, when the user can be asked: one thing at a time, so
     * call again once they answer. First that this app be exempt from
     * battery optimisation (vendors kill its service otherwise, and only an
     * exempt app's alarm may restart it); then the notification permission
     * (else its service shows in the drawer not at all). False when nothing
     * is left to ask.
     */
    fun ask(a: Activity): Boolean {
        if (!exempt(a)) {
            val i = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${a.packageName}"))
            return runCatching { a.startActivity(i) }.isSuccess
        }
        if (Build.VERSION.SDK_INT < 33 ||
            a.checkSelfPermission(POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return false
        a.requestPermissions(arrayOf(POST_NOTIFICATIONS), 0)
        return true
    }

    /** This app is exempt from battery optimisation, as [ask] asks first. */
    fun exempt(c: Context): Boolean =
        c.getSystemService(PowerManager::class.java)?.isIgnoringBatteryOptimizations(c.packageName) == true
}

/** Holds this app's mailbox while the app listens: the relay connection,
 *  its pings, and a reconnect at each network that comes up. */
class Broker : Service() {
    /** The default network and its addresses: another, or new ones there,
     *  move the connection at once (no ping on the old). Each kind keeps
     *  the silence its NAT allows, so a steady network is rarely pinged. */
    private var at: Network? = null
    private var addrs: Set<java.net.InetAddress> = emptySet()
    private val net = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(n: Network, lp: LinkProperties) {
            val a = lp.linkAddresses.map { it.address }.toSet()
            if (n == at && a == addrs) return
            at = n
            addrs = a
            val c = getSystemService(ConnectivityManager::class.java)?.getNetworkCapabilities(n)
            val kind = when {
                c == null -> "other"
                c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cell"
                c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "eth"
                else -> "other"
            }
            thread { runCatching { Native.moved(kind) }; beat(this@Broker) }
        }
    }

    override fun onCreate() {
        super.onCreate()
        Pushir.id(Native.start(File(filesDir, KEY).path))
        reader
        thread { beat(this) }
        getSystemService(ConnectivityManager::class.java)?.registerDefaultNetworkCallback(net)
    }

    /** The mailbox let go with its service. */
    override fun onDestroy() {
        Pushir.refused = "stopped"
        Native.stop()
        runCatching { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(net) }
        super.onDestroy()
    }

    override fun onStartCommand(i: Intent?, flags: Int, startId: Int): Int {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("pushir", "Push", NotificationManager.IMPORTANCE_MIN))
        val n = Notification.Builder(this, "pushir").setContentTitle("Ready for pushes")
            .setSmallIcon(android.R.drawable.stat_notify_sync).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
        else startForeground(1, n)
        Pushir.refused = null
        return START_STICKY
    }

    override fun onBind(i: Intent?): IBinder = Binder()

    companion object {
        /** Frames, read on one thread for the process. */
        private val reader by lazy { thread(isDaemon = true) { while (true) Pushir.frame(Native.next()) } }
    }
}

/** Boot or an update: the app's start (in its `Application`) decides; this
 *  gives its service the foreground start Android allows here. */
class Boot : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        if (Pushir.on) broker(c, true)
    }
}

/** The alarm: the phone stays awake for the ping's answer, or for finding
 *  the connection dead and making another (up to the kick's 30 s), no
 *  longer. An app that no longer listens pings no more. */
class Beat : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        if (!Pushir.on) return
        broker(c, true)
        val lock = c.getSystemService(PowerManager::class.java)
            ?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "pushir:beat")
        lock?.acquire(35_000)
        thread { try { beat(c) } finally { if (lock?.isHeld == true) lock.release() } }
    }
}
