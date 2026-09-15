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

public class AegsVpnService extends VpnService implements Runnable {
    private static final String TAG = "AegsVpnService";
    private static final String CHANNEL_ID = "aegs_vpn_channel";
    private static final int NOTIF_ID = 1001;

    private Thread mThread;
    private ParcelFileDescriptor mInterface;
    private volatile boolean mRunning = false;

    private String mServerIp = "185.196.8.10";
    private int mServerPort = 50001;
    private String mToken = "default";
    private boolean mSplitTunnel = true;

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
            mServerIp = intent.getStringExtra("SERVER_IP");
            mServerPort = intent.getIntExtra("SERVER_PORT", 50001);
            mToken = intent.getStringExtra("TOKEN");
            mSplitTunnel = intent.getBooleanExtra("SPLIT_TUNNEL", true);
        }

        createNotificationChannel();
        Notification notif = buildNotification(mSplitTunnel ? "Защищено • Умный обход (Банки напрямую)" : "Защищено • Весь трафик");
        startForeground(NOTIF_ID, notif);

        if (mThread == null || !mThread.isAlive()) {
            mRunning = true;
            mThread = new Thread(this, "AegsVpnThread");
            mThread.start();
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
            channel.setDescription("Статус активного подключения AEGS");
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
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }

    @Override
    public void run() {
        try {
            Builder builder = new Builder();
            builder.setSession("AEGS Titan");
            builder.addAddress("10.8.0.2", 24);
            builder.addDnsServer("1.1.1.1");
            builder.addDnsServer("8.8.8.8");
            builder.addRoute("0.0.0.0", 0);
            builder.setMtu(1400);

            // Apply Split Tunneling exclusions
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
                Log.e(TAG, "Failed to establish VPN interface");
                return;
            }

            DatagramChannel tunnel = DatagramChannel.open();
            tunnel.connect(new InetSocketAddress(mServerIp, mServerPort));
            protect(tunnel.socket());
            tunnel.configureBlocking(true);

            FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(mInterface.getFileDescriptor());

            byte[] packet = new byte[32768];
            ByteBuffer udpBuf = ByteBuffer.allocate(32768);

            while (mRunning) {
                int len = in.read(packet);
                if (len > 0) {
                    udpBuf.clear();
                    // Inject QUIC mimicry header: 0xC0 (Long Header Initial)
                    udpBuf.put((byte) 0xC0);
                    udpBuf.putInt(0x00000001); // QUIC version 1
                    udpBuf.put(packet, 0, len);
                    udpBuf.flip();
                    tunnel.write(udpBuf);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "VPN loop error: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    private void stopVpn() {
        mRunning = false;
        if (mThread != null) {
            mThread.interrupt();
        }
        cleanup();
        stopForeground(true);
        stopSelf();
    }

    private void cleanup() {
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
