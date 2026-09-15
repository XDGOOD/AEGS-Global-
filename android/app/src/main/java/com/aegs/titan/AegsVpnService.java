package com.aegs.titan;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Full-Duplex Bi-Directional AEGS v6 Titan VPN Service
 *
 * Implements:
 * - RFC 7748 X25519 Curve25519 & ChaCha20-Poly1305 AEGS Protocol Handshake
 * - Config parsing from HANDSHAKE_RESP (Assigned IP + MTU)
 * - Concurrent TUN -> UDP worker (reads from TUN, bimodal padding, ChaCha20 header mask + Poly1305 AEAD, sends via UDP)
 * - Concurrent UDP -> TUN worker (reads UDP, unmasks header, verifies Poly1305 AAD tag, drops chaff, writes plaintext to TUN)
 * - Battery-friendly adaptive chaffing / keep-alive with exponential backoff on idle
 * - Comprehensive lifecycle management and resource cleanup
 */
public class AegsVpnService extends VpnService implements Runnable {
    private static final String TAG = "AegsVpnService";
    private static final String CHANNEL_ID = "aegs_vpn_channel";
    private static final int NOTIF_ID = 1001;

    private Thread mMainThread;
    private Thread mTunToUdpThread;
    private Thread mUdpToTunThread;
    private Thread mChaffThread;

    private ParcelFileDescriptor mInterface;
    private DatagramChannel mTunnel;
    private final Object mTunnelLock = new Object();
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    private String mServerIp = "185.196.8.10";
    private int mServerPort = 50001;
    private String mToken = "aegs_secure_token_titan_v6";
    private boolean mSplitTunnel = true;
    private boolean mAdaptiveChaff = true;
    private int mProtocolMode = SettingsActivity.PROTO_STEALTH;

    private final AtomicLong mTxSeq = new AtomicLong(0);
    private final AtomicLong mLastActivityTime = new AtomicLong(System.currentTimeMillis());

    private AegsProtocol.HandshakeResult mSession;

    private static final String[] BYPASS_PACKAGES = {
            "ru.sberbankmobile",
            "com.idamob.tinkoff.android",
            "ru.vtb24.mobilebanking",
            "ru.alfabank.mobile.android",
            "ru.gosuslugi.net",
            "ru.yandex.searchplugin",
            "com.vkontakte.android",
            "ru.ozon.app.android",
            "com.wildberries.ru"
    };

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            String action = intent.getAction();
            if ("STOP".equals(action)) {
                stopVpn();
                return START_NOT_STICKY;
            }
            if (intent.hasExtra("SERVER_IP")) mServerIp = intent.getStringExtra("SERVER_IP");
            if (intent.hasExtra("SERVER_PORT")) mServerPort = intent.getIntExtra("SERVER_PORT", 50001);
            if (intent.hasExtra("TOKEN")) mToken = intent.getStringExtra("TOKEN");
            if (intent.hasExtra("SPLIT_TUNNEL")) mSplitTunnel = intent.getBooleanExtra("SPLIT_TUNNEL", true);
            if (intent.hasExtra("ADAPTIVE_CHAFF")) mAdaptiveChaff = intent.getBooleanExtra("ADAPTIVE_CHAFF", true);
            if (intent.hasExtra("PROTOCOL_MODE")) mProtocolMode = intent.getIntExtra("PROTOCOL_MODE", SettingsActivity.PROTO_STEALTH);
        }

        createNotificationChannel();
        Notification notif = buildNotification("Защита активна • AEGS Titan v6.5");
        startForeground(NOTIF_ID, notif);

        if (mMainThread == null || !mMainThread.isAlive()) {
            mRunning.set(true);
            mMainThread = new Thread(this, "AegsMainThread");
            mMainThread.start();
        }

        return START_STICKY;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "AEGS VPN Status",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Статус защищенного туннеля AEGS Titan");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    private Notification buildNotification(String text) {
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("AEGS Titan v6.5")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }

    @Override
    public void run() {
        try {
            Log.i(TAG, "[AEGS] Starting handshake with " + mServerIp + ":" + mServerPort);

            mTunnel = DatagramChannel.open();
            mTunnel.connect(new InetSocketAddress(mServerIp, mServerPort));
            protect(mTunnel.socket());

            // Phase 1: DPI Pre-Bypass Decoys
            if (mProtocolMode == SettingsActivity.PROTO_ILLUSION) {
                byte[] stunDecoy = AegsProtocol.buildStunDecoy();
                mTunnel.write(ByteBuffer.wrap(stunDecoy));
                Thread.sleep(50);
            } else if (mProtocolMode == SettingsActivity.PROTO_STEALTH) {
                byte[] quicDecoy = AegsProtocol.buildQuicInitialDecoy();
                mTunnel.write(ByteBuffer.wrap(quicDecoy));
                Thread.sleep(50);
            }

            // Phase 2: Cryptographic Handshake
            byte[] keyId = AegsProtocol.deriveKeyId(mToken);
            byte[] masterKey = AegsProtocol.deriveMasterKey(mToken, keyId);
            AegsProtocol.X25519KeyPair ephKeyPair = AegsProtocol.generateX25519KeyPair();

            byte[] initPkt = AegsProtocol.buildHandshakeInit(keyId, masterKey, ephKeyPair.publicKey);

            boolean handshakeOk = false;
            ByteBuffer respBuf = ByteBuffer.allocate(2048);

            mTunnel.configureBlocking(false);
            Selector selector = Selector.open();
            mTunnel.register(selector, SelectionKey.OP_READ);

            for (int attempt = 0; attempt < 3 && mRunning.get(); attempt++) {
                mTunnel.write(ByteBuffer.wrap(initPkt));

                if (selector.select(2500) > 0) {
                    selector.selectedKeys().clear();
                    respBuf.clear();
                    int readBytes = mTunnel.read(respBuf);
                    if (readBytes >= 80) {
                        respBuf.flip();
                        byte[] respBytes = new byte[readBytes];
                        respBuf.get(respBytes);

                        try {
                            mSession = AegsProtocol.processHandshakeResp(
                                    respBytes, readBytes, keyId, masterKey, ephKeyPair.privateKey);
                            handshakeOk = true;
                            Log.i(TAG, "[AEGS] Handshake successful! Assigned IP: " + mSession.assignedIp + " MTU: " + mSession.mtu);
                            break;
                        } catch (Exception e) {
                            Log.w(TAG, "[AEGS] Failed to parse Handshake response: " + e.getMessage());
                        }
                    }
                } else {
                    Log.w(TAG, "[AEGS] Handshake attempt " + (attempt + 1) + " timed out, retrying...");
                }
            }

            try { selector.close(); } catch (Exception ignored) {}

            if (!handshakeOk || mSession == null) {
                Log.e(TAG, "[AEGS] Failed to complete handshake with server");
                stopVpn();
                return;
            }

            // Phase 3: Configure Virtual TUN Interface
            Builder builder = new Builder();
            builder.setSession("AEGS Titan (" + mSession.assignedIp + ")");
            builder.addAddress(mSession.assignedIp, 24);
            builder.addDnsServer("10.8.0.1"); // Enforce tunnel DNS to prevent leaks
            builder.addDnsServer("1.1.1.1");
            builder.addRoute("0.0.0.0", 0);
            builder.setMtu(mSession.mtu);

            if (mSplitTunnel && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                PackageManager pm = getPackageManager();
                for (String pkg : BYPASS_PACKAGES) {
                    try {
                        pm.getPackageInfo(pkg, 0);
                        builder.addDisallowedApplication(pkg);
                    } catch (PackageManager.NameNotFoundException ignored) {}
                }
            }

            mInterface = builder.establish();
            if (mInterface == null) {
                Log.e(TAG, "[AEGS] Failed to establish TUN interface");
                stopVpn();
                return;
            }

            mTunnel.configureBlocking(true);

            // Phase 4: Launch Concurrent Bi-Directional Workers
            startWorkers();

        } catch (Exception e) {
            Log.e(TAG, "[AEGS] Fatal VPN error: " + e.getMessage(), e);
            stopVpn();
        }
    }

    private void startWorkers() {
        final FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());
        final FileOutputStream out = new FileOutputStream(mInterface.getFileDescriptor());

        // Worker 1: TUN -> UDP Egress Thread
        mTunToUdpThread = new Thread(() -> {
            byte[] ipBuf = new byte[32768];
            while (mRunning.get()) {
                try {
                    int len = in.read(ipBuf);
                    if (len > 0) {
                        long seq = mTxSeq.incrementAndGet();
                        mLastActivityTime.set(System.currentTimeMillis());

                        byte[] wire = AegsProtocol.buildDataPacket(
                                ipBuf, len, mSession.keyId, mSession.maskKey,
                                mSession.sendKey, seq, false);

                        synchronized (mTunnelLock) {
                            if (mTunnel != null && mTunnel.isOpen()) {
                                mTunnel.write(ByteBuffer.wrap(wire));
                            }
                        }
                    }
                } catch (Exception e) {
                    if (!mRunning.get()) break;
                    Log.e(TAG, "[AEGS] TUN read error: " + e.getMessage());
                }
            }
        }, "AegsTunToUdp");
        mTunToUdpThread.start();

        // Worker 2: UDP -> TUN Ingress Thread
        mUdpToTunThread = new Thread(() -> {
            ByteBuffer udpBuf = ByteBuffer.allocate(65535);
            while (mRunning.get()) {
                try {
                    udpBuf.clear();
                    int readBytes = mTunnel.read(udpBuf);
                    if (readBytes > 0) {
                        udpBuf.flip();
                        byte[] rawPacket = new byte[readBytes];
                        udpBuf.get(rawPacket);

                        byte[] plainIp = AegsProtocol.parseDataPacket(
                                rawPacket, readBytes, mSession.keyId, mSession.maskKey, mSession.recvKey);

                        if (plainIp != null) {
                            if (plainIp.length > 0) {
                                out.write(plainIp);
                            }
                            mLastActivityTime.set(System.currentTimeMillis());
                        }
                    }
                } catch (Exception e) {
                    if (!mRunning.get()) break;
                    Log.e(TAG, "[AEGS] UDP receive error: " + e.getMessage());
                }
            }
        }, "AegsUdpToTun");
        mUdpToTunThread.start();

        // Worker 3: Adaptive Chaffing Engine (Battery & Data Saver)
        mChaffThread = new Thread(() -> {
            while (mRunning.get()) {
                try {
                    long idleMs = System.currentTimeMillis() - mLastActivityTime.get();
                    long sleepMs = 800;

                    if (mAdaptiveChaff) {
                        if (idleMs > 30000) {
                            sleepMs = 15000; // Deep idle: 15s interval
                        } else if (idleMs > 10000) {
                            sleepMs = 5000;  // Moderate idle: 5s interval
                        } else {
                            sleepMs = 800;   // Active stream: 800ms
                        }
                    }

                    Thread.sleep(sleepMs);

                    if (mRunning.get() && mSession != null) {
                        long seq = mTxSeq.incrementAndGet();
                        byte[] chaffPkt = AegsProtocol.buildDataPacket(
                                new byte[0], 0, mSession.keyId, mSession.maskKey,
                                mSession.sendKey, seq, true);

                        synchronized (mTunnelLock) {
                            if (mTunnel != null && mTunnel.isOpen()) {
                                mTunnel.write(ByteBuffer.wrap(chaffPkt));
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    break;
                } catch (Exception ignored) {}
            }
        }, "AegsChaffEngine");
        mChaffThread.start();
    }

    private void stopVpn() {
        mRunning.set(false);
        if (mMainThread != null) mMainThread.interrupt();
        if (mTunToUdpThread != null) mTunToUdpThread.interrupt();
        if (mUdpToTunThread != null) mUdpToTunThread.interrupt();
        if (mChaffThread != null) mChaffThread.interrupt();

        cleanup();
        try {
            stopForeground(true);
        } catch (Exception ignored) {}
        stopSelf();
    }

    private void cleanup() {
        synchronized (mTunnelLock) {
            try {
                if (mTunnel != null) {
                    mTunnel.close();
                    mTunnel = null;
                }
            } catch (Exception ignored) {}
        }

        try {
            if (mInterface != null) {
                mInterface.close();
                mInterface = null;
            }
        } catch (Exception ignored) {}
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
