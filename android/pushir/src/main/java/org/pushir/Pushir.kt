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
import android.net.Network
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import java.io.File
import kotlin.concurrent.thread

private const val ATTACH = "org.pushir.ATTACH"
private const val WAKE = "org.pushir.WAKE"
private const val HELLO = 1
private const val ID = 2
private const val PUSH = 3
private val main = Handler(Looper.getMainLooper())

/** The app's native library links the pushir crate with feature `jni`. */
internal object Native {
    @JvmStatic external fun start(path: String): String
    @JvmStatic external fun stop()
    @JvmStatic external fun next(): ByteArray
    @JvmStatic external fun route(secret: ByteArray): ByteArray
    @JvmStatic external fun hears(route: ByteArray, frame: ByteArray): Boolean
    @JvmStatic external fun open(secret: ByteArray, frame: ByteArray): ByteArray?
    @JvmStatic external fun kick(): Long
}

private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
private fun String.unhex() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/** Whole or not at all. */
private fun File.put(b: ByteArray) = runCatching { File("$path.new").apply { writeBytes(b) }.renameTo(this) }

/**
 * The group's owner, of its apps listening (a broker enabled: [Pushir.stop]
 * disables it): one Android lets run asleep (exempt from battery
 * optimisation) before one it may stop, then the first installed. The same
 * answer in every app: one app not listening, or stopped asleep, holds
 * nobody's connection.
 */
internal fun owner(c: Context): ComponentName? {
    val pm = c.packageManager
    val power = c.getSystemService(PowerManager::class.java)
    return group(c).minWithOrNull(compareBy({ power?.isIgnoringBatteryOptimizations(it.packageName) != true },
        { pm.getPackageInfo(it.packageName, 0).firstInstallTime }, { it.packageName }))
        ?.let { ComponentName(it.packageName, it.name) }
}

/** The group's brokers enabled: its apps signed by this one's key. */
private fun group(c: Context): List<ServiceInfo> {
    val pm = c.packageManager
    return pm.queryIntentServices(Intent(ATTACH), 0).map { it.serviceInfo }
        .filter { pm.checkSignatures(c.packageName, it.packageName) == PackageManager.SIGNATURE_MATCH }
}

/** This app's broker started if this app is the owner, else stopped (it
 *  lets the mailbox go once its clients follow the owner); whether it is.
 *  Not started from the background on Android 12+, unless exempt: then the
 *  system's own restart of the service stands. */
private fun ownerStart(c: Context): Boolean {
    val broker = Intent(c, Broker::class.java)
    val mine = owner(c)?.packageName == c.packageName
    runCatching { if (mine) c.startForegroundService(broker) else c.stopService(broker) }
    return mine
}

/** This app's broker in the group's election, or out of it. */
private fun elect(c: Context, on: Boolean) = runCatching {
    val state = if (on) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        else PackageManager.COMPONENT_ENABLED_STATE_DISABLED
    c.packageManager.setComponentEnabledSetting(ComponentName(c, Broker::class.java),
        state, PackageManager.DONT_KILL_APP)
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
    // The broker bound: another, once the group elects again, is followed.
    private var to: ComponentName? = null
    /** Left by [stop]: nothing binds again until [start]. */
    private var left = false

    private val me = Messenger(Handler(Looper.getMainLooper()) { m ->
        runCatching {
            when (m.what) {
                ID -> {
                    m.data.getByteArray("key")?.let(::keep)
                    m.data.getString("id")?.let(onId)
                }
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

    /** The owner's mailbox key, kept: should this app become the owner (the
     *  owner removed), it holds the same mailbox, and every lane stands. */
    private fun keep(k: ByteArray) {
        val f = File(app.filesDir, "pushir.key")
        if (k.size == 32 && runCatching { f.readBytes() }.getOrNull()?.contentEquals(k) != true) f.put(k)
    }

    /**
     * From an activity, when the user can be asked: one thing at a time, so
     * call again once they answer. First that the owner be exempt from
     * battery optimisation (vendors kill its service otherwise, and only an
     * exempt app's alarm may restart it): this app, asked, as one exempt is
     * elected before one that is not; then, in the owner, the notification
     * permission (else its service shows in the drawer not at all). False
     * when nothing is left to ask.
     */
    fun ask(a: Activity): Boolean {
        val o = owner(a)?.packageName ?: return false
        if (!exempt(a)) {
            val i = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${a.packageName}"))
            return runCatching { a.startActivity(i) }.isSuccess
        }
        if (o != a.packageName || Build.VERSION.SDK_INT < 33 ||
            a.checkSelfPermission(POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return false
        a.requestPermissions(arrayOf(POST_NOTIFICATIONS), 0)
        return true
    }

    /** The owner (perhaps another app of the group) is exempt from battery
     *  optimisation, as [ask] asks first: for the app's settings to show. */
    fun exempt(c: Context): Boolean {
        val o = owner(c)?.packageName ?: return false
        return c.getSystemService(PowerManager::class.java)?.isIgnoringBatteryOptimizations(o) == true
    }

    /** [lib]: the app's native library. [onId]: the mailbox id, for the lane the app gives its senders. */
    fun start(c: Context, lib: String, secret: ByteArray, onId: (String) -> Unit, onPush: (ByteArray) -> Unit) {
        System.loadLibrary(lib)
        app = c.applicationContext
        this.secret = secret
        this.onId = onId
        this.onPush = onPush
        // After a [stop] just before: it runs on the main thread too.
        main.post {
            left = false
            elect(app, true)
            ownerStart(app)
        }
        bind()
    }

    /** The owner as the group elects it now (an app's battery setting
     *  changed, or one joined or left): bound to, if another than before. */
    internal fun follow() {
        main.post { if (bound && owner(app) != to) rebind() }
    }

    /**
     * This app leaves the connection: unbound, its own broker stopped and
     * out of the group's election, so this app holds no socket and the
     * group's next app holds the connection. [start] joins again.
     */
    fun stop(c: Context) = main.post {
        left = true
        if (bound) runCatching { app.unbindService(conn) }
        bound = false
        runCatching { c.applicationContext.stopService(Intent(c, Broker::class.java)) }
        elect(c.applicationContext, false)
    }

    private fun bind() = main.post {
        if (left) return@post
        val o = owner(app) ?: return@post
        if (!bound) bound = app.bindService(Intent(ATTACH).setComponent(o), conn, Context.BIND_AUTO_CREATE)
        if (bound) to = o
    }

    private fun rebind() {
        if (left) return
        runCatching { app.unbindService(conn) }
        bound = false
        to = null
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
    private var key: ByteArray? = null

    /** Held frames survive the owner's restart: they wait on flash, sealed. */
    private val heldFile get() = File(filesDir, "pushir.held")
    private fun save() = heldFile.put(held.fold(ByteArray(0), ByteArray::plus))

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
            tell(to, ID, Bundle().apply { putString("id", id); putByteArray("key", key) })
            if (held.removeAll { Native.hears(route, it) && tell(to, PUSH, Bundle().apply { putByteArray("d", it) }) }) save()
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
        save()
        (lane?.value as? String)?.let { sendBroadcast(Intent(WAKE).setPackage(it)) }
    }

    override fun onCreate() {
        super.onCreate()
        val k = File(filesDir, "pushir.key")
        id = Native.start(k.path)
        key = runCatching { k.readBytes() }.getOrNull()
        live = this
        reader
        // Each held frame again: its app woken.
        runCatching { heldFile.readBytes() }.getOrNull()?.let { b ->
            for (i in 0 until b.size / 1024) deliver(b.copyOfRange(i * 1024, i * 1024 + 1024))
        }
        // Set the alarm; and at each network that comes up, reconnect at once.
        thread { beat(this) }
        getSystemService(ConnectivityManager::class.java)?.registerDefaultNetworkCallback(net)
        // The group elects again: an owner displaced stops, every app follows.
        group(this).forEach { if (it.packageName != packageName) sendBroadcast(Intent(WAKE).setPackage(it.packageName)) }
    }

    private val net = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(n: Network) { thread { beat(this@Broker) } }
    }

    /** The mailbox let go with its broker: the next owner holds it alone. */
    override fun onDestroy() {
        Native.stop()
        live = null
        runCatching { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(net) }
        super.onDestroy()
    }

    companion object {
        /** The broker that runs: frames, read on one thread for the process, go to it. */
        private var live: Broker? = null
        private val reader by lazy {
            thread(isDaemon = true) {
                while (true) {
                    val f = Native.next()
                    main.post { live?.deliver(f) }
                }
            }
        }
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

/** A frame waits for this app (starting its process is enough), or a
 *  broker started: perhaps another owner, to follow. */
class Wake : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        ownerStart(c)
        Pushir.follow()
    }
}

/** Boot, an update, or a package removed: perhaps the owner, and this app the next. */
class Boot : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        ownerStart(c)
    }
}

/** The alarm: the phone stays awake for the ping's answer, no longer. An
 *  owner elected out (another app exempt since) stops, pings no more, and
 *  follows the new one: its clients follow at that one's start. */
class Beat : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        if (!ownerStart(c)) return Pushir.follow()
        val done = goAsync()
        thread { beat(c); done.finish() }
    }
}
