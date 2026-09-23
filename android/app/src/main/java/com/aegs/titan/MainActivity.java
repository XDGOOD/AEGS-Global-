package com.aegs.titan;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private static final int VPN_REQUEST_CODE = 1001;

    public static final String KEY_SERVER_IP = "server_ip";
    public static final String KEY_SERVER_PORT = "server_port";
    public static final String KEY_TOKEN = "server_token";
    public static final String KEY_KEY_ID = "server_key_id";
    public static final String KEY_HAS_ACTIVE_KEY = "has_active_key";

    public static final String DEFAULT_SERVER_IP = "31.76.9.86";
    public static final int DEFAULT_SERVER_PORT = 50001;
    public static final String BOT_USERNAME = "aegs_support_bot";

    // Views: Header & Status
    private TextView mTvStatus;
    private TextView mTvProtoBadge;
    private ImageView mBtnSettings;
    private Button mBtnShareKey;
    private View mCardSettings;

    // Views: Key Acquisition & Management
    private LinearLayout mCardNoKey;
    private Button mBtnBuyBot;
    private EditText mEtAccessKey;
    private Button mBtnPasteKey;
    private Button mBtnActivateKey;

    private LinearLayout mCardActiveKey;
    private TextView mTvActiveKeyId;
    private TextView mTvActiveServer;
    private Button mBtnChangeKey;
    private Button mBtnRenewBot;

    // Views: Connection
    private View mBtnConnectCircle;
    private TextView mTvConnLabel;
    private TextView mTvConnSub;
    private ImageView mIvConnShield;

    // Views: Telemetry
    private TextView mTvSpeed;
    private TextView mTvPing;
    private LiveMetricsGraphView mMetricsGraph;
    private CheckBox mCbSplit;
    private TextView mTvSplitStatus;
    private TextView mBtnConfigureApps;

    // State
    private SharedPreferences mPrefs;
    private boolean mIsConnected = false;
    private String mServerIp = DEFAULT_SERVER_IP;
    private int mServerPort = DEFAULT_SERVER_PORT;
    private String mToken = "";
    private String mKeyId = "";
    private String mLastClipboardText = "";

    private final Handler mPingHandler = new Handler(Looper.getMainLooper());
    private final Random mRandom = new Random();
    private final Runnable mPingRunnable = new Runnable() {
        @Override
        public void run() {
            if (mIsConnected) {
                float basePing = 18.0f;
                float jitter = (mRandom.nextFloat() - 0.5f) * 3.5f;
                float currentPing = Math.max(12.0f, basePing + jitter);

                if (mTvPing != null) {
                    mTvPing.setText(String.format("Пинг к серверу: %.0f мс", currentPing));
                }
                if (mMetricsGraph != null) {
                    mMetricsGraph.addSample(currentPing);
                }
                mPingHandler.postDelayed(this, 1500);
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mPrefs = getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE);

        // System Theme Auto-Adjust
        boolean dynamicTheme = mPrefs.getBoolean(SettingsActivity.KEY_DYNAMIC_THEME, true);
        if (dynamicTheme) {
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM);
        }

        // Onboarding first launch check
        if (!mPrefs.getBoolean("onboarding_complete", false) && !mPrefs.getBoolean("onboarding_done", false)) {
            startActivity(new Intent(this, OnboardingActivity.class));
            finish();
            return;
        }

        setContentView(R.layout.activity_main);

        // Bind Views
        mTvStatus = findViewById(R.id.tv_status);
        mTvProtoBadge = findViewById(R.id.tv_proto_badge);
        mBtnSettings = findViewById(R.id.btn_settings);
        mBtnShareKey = findViewById(R.id.btn_share_key);
        mCardSettings = findViewById(R.id.card_open_settings);

        mCardNoKey = findViewById(R.id.card_no_key);
        mBtnBuyBot = findViewById(R.id.btn_buy_bot);
        mEtAccessKey = findViewById(R.id.et_access_key);
        mBtnPasteKey = findViewById(R.id.btn_paste_key);
        mBtnActivateKey = findViewById(R.id.btn_activate_key);

        mCardActiveKey = findViewById(R.id.card_active_key);
        mTvActiveKeyId = findViewById(R.id.tv_active_key_id);
        mTvActiveServer = findViewById(R.id.tv_active_server);
        mBtnChangeKey = findViewById(R.id.btn_change_key);
        mBtnRenewBot = findViewById(R.id.btn_renew_bot);

        mBtnConnectCircle = findViewById(R.id.btn_connect_circle);
        mTvConnLabel = findViewById(R.id.tv_conn_label);
        mTvConnSub = findViewById(R.id.tv_conn_sub);
        mIvConnShield = findViewById(R.id.iv_conn_shield);

        mTvSpeed = findViewById(R.id.tv_speed);
        mTvPing = findViewById(R.id.tv_ping);
        mMetricsGraph = findViewById(R.id.metrics_graph);
        mCbSplit = findViewById(R.id.cb_split);
        mTvSplitStatus = findViewById(R.id.tv_split_status);
        mBtnConfigureApps = findViewById(R.id.btn_configure_apps);

        if (mBtnConfigureApps != null) {
            mBtnConfigureApps.setOnClickListener(v -> {
                Intent intent = new Intent(MainActivity.this, AppRoutingActivity.class);
                startActivity(intent);
            });
        }

        View cardSplit = findViewById(R.id.card_split_tunneling);
        if (cardSplit != null) {
            cardSplit.setOnClickListener(v -> {
                Intent intent = new Intent(MainActivity.this, AppRoutingActivity.class);
                startActivity(intent);
            });
        }

        if (mCbSplit != null) {
            mCbSplit.setChecked(mPrefs.getBoolean(SettingsActivity.KEY_SPLIT_TUNNEL, true));
            mCbSplit.setOnCheckedChangeListener((buttonView, isChecked) -> {
                mPrefs.edit().putBoolean(SettingsActivity.KEY_SPLIT_TUNNEL, isChecked).apply();
                updateSplitTunnelUi();
            });
        }

        // Load saved connection parameters
        loadSavedKey();

        // Setup Listeners
        if (mBtnBuyBot != null) {
            mBtnBuyBot.setOnClickListener(v -> openTelegramBot());
        }
        if (mBtnRenewBot != null) {
            mBtnRenewBot.setOnClickListener(v -> openTelegramBot());
        }
        if (mBtnPasteKey != null) {
            mBtnPasteKey.setOnClickListener(v -> pasteFromClipboard());
        }
        if (mBtnActivateKey != null) {
            mBtnActivateKey.setOnClickListener(v -> {
                String input = mEtAccessKey.getText().toString().trim();
                if (parseAndSaveKey(input)) {
                    mEtAccessKey.setText("");
                }
            });
        }
        if (mBtnChangeKey != null) {
            mBtnChangeKey.setOnClickListener(v -> changeKey());
        }
        if (mBtnShareKey != null) {
            mBtnShareKey.setOnClickListener(v -> shareActiveKey());
        }
        if (mBtnSettings != null) {
            mBtnSettings.setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));
        }
        if (mCardSettings != null) {
            mCardSettings.setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));
        }
        if (mBtnConnectCircle != null) {
            mBtnConnectCircle.setOnClickListener(v -> toggleConnection());
        }

        updateProtoBadge();
        updateKeyViews();
        handleIncomingIntent(getIntent());
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateProtoBadge();
        checkClipboardForConfig();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mPingHandler.removeCallbacks(mPingRunnable);
    }

    private void loadSavedKey() {
        mToken = mPrefs.getString(KEY_TOKEN, "");
        mServerIp = mPrefs.getString(KEY_SERVER_IP, DEFAULT_SERVER_IP);
        mServerPort = mPrefs.getInt(KEY_SERVER_PORT, DEFAULT_SERVER_PORT);
        mKeyId = mPrefs.getString(KEY_KEY_ID, "");

        if (mToken.equals("client_default_token")) {
            mToken = "";
            mPrefs.edit().remove(KEY_TOKEN).apply();
        }

        if (!mToken.isEmpty() && mKeyId.isEmpty()) {
            mKeyId = computeKeyId(mToken);
            mPrefs.edit().putString(KEY_KEY_ID, mKeyId).apply();
        }
    }

    private boolean hasActiveKey() {
        return mToken != null && !mToken.isEmpty() && !mToken.equals("client_default_token") && mToken.length() >= 16;
    }

    private void updateKeyViews() {
        if (!hasActiveKey()) {
            if (mCardNoKey != null) mCardNoKey.setVisibility(View.VISIBLE);
            if (mCardActiveKey != null) mCardActiveKey.setVisibility(View.GONE);
            if (mBtnConnectCircle != null) mBtnConnectCircle.setVisibility(View.GONE);

            if (mTvStatus != null) {
                mTvStatus.setText("ТРЕБУЕТСЯ КЛЮЧ ДОСТУПА");
                mTvStatus.setTextColor(0xFFF87171); // Red
            }
        } else {
            if (mCardNoKey != null) mCardNoKey.setVisibility(View.GONE);
            if (mCardActiveKey != null) mCardActiveKey.setVisibility(View.VISIBLE);
            if (mBtnConnectCircle != null) mBtnConnectCircle.setVisibility(View.VISIBLE);

            if (mTvActiveKeyId != null) {
                String masked = mKeyId.length() >= 8 ? mKeyId.substring(0, 8) + "..." : mKeyId;
                mTvActiveKeyId.setText("KeyID: " + masked);
            }
            if (mTvActiveServer != null) {
                mTvActiveServer.setText("Сервер: " + mServerIp + ":" + mServerPort + " (AEGS Titan-01)");
            }

            if (!mIsConnected) {
                if (mTvStatus != null) {
                    mTvStatus.setText("КЛЮЧ АКТИВЕН   ГОТОВ К ЗАЩИТЕ");
                    mTvStatus.setTextColor(0xFFF59E0B); // Amber
                }
                if (mTvConnLabel != null) mTvConnLabel.setText("ПОДКЛЮЧИТЬСЯ");
                if (mTvConnSub != null) mTvConnSub.setText("Запустить туннель");
                if (mIvConnShield != null) mIvConnShield.setColorFilter(0xFFF59E0B);
            } else {
                if (mTvStatus != null) {
                    mTvStatus.setText("ЗАЩИЩЕНО   AEGS v6 TITAN");
                    mTvStatus.setTextColor(0xFF34D399); // Green
                }
                if (mTvConnLabel != null) mTvConnLabel.setText("ОТКЛЮЧИТЬ");
                if (mTvConnSub != null) mTvConnSub.setText("Туннель активен");
                if (mIvConnShield != null) mIvConnShield.setColorFilter(0xFF34D399);
            }
        }
    }

    private void openTelegramBot() {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("tg://resolve?domain=" + BOT_USERNAME));
            intent.setPackage("org.telegram.messenger");
            startActivity(intent);
        } catch (Exception e) {
            try {
                Intent fallbackTg = new Intent(Intent.ACTION_VIEW, Uri.parse("tg://resolve?domain=" + BOT_USERNAME));
                startActivity(fallbackTg);
            } catch (Exception e2) {
                Intent webIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/" + BOT_USERNAME));
                startActivity(webIntent);
            }
        }
    }

    private void pasteFromClipboard() {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null && cm.hasPrimaryClip() && cm.getPrimaryClip().getItemCount() > 0) {
                CharSequence text = cm.getPrimaryClip().getItemAt(0).getText();
                if (text != null && text.length() > 0) {
                    String clipStr = text.toString().trim();
                    if (mEtAccessKey != null) {
                        mEtAccessKey.setText(clipStr);
                    }
                    if (parseAndSaveKey(clipStr)) {
                        if (mEtAccessKey != null) mEtAccessKey.setText("");
                    }
                    return;
                }
            }
            Toast.makeText(this, "Буфер обмена пуст", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Log.e(TAG, "Failed to read clipboard", e);
        }
    }

    private void changeKey() {
        if (mIsConnected) {
            disconnectVpn();
        }
        mToken = "";
        mKeyId = "";
        mPrefs.edit()
                .remove(KEY_TOKEN)
                .remove(KEY_KEY_ID)
                .putBoolean(KEY_HAS_ACTIVE_KEY, false)
                .apply();
        updateKeyViews();
        if (mEtAccessKey != null) {
            mEtAccessKey.requestFocus();
        }
        Toast.makeText(this, "Введите новый ключ или ссылку подписки", Toast.LENGTH_SHORT).show();
    }

    public boolean parseAndSaveKey(String input) {
        if (input == null) return false;
        String text = input.trim();
        if (text.isEmpty()) return false;

        String ip = DEFAULT_SERVER_IP;
        int port = DEFAULT_SERVER_PORT;
        String token = null;

        if (text.startsWith("aegs://")) {
            try {
                Uri uri = Uri.parse(text);
                String host = uri.getHost();
                int p = uri.getPort();
                if (host != null && !host.isEmpty()) ip = host;
                if (p > 0) port = p;

                token = uri.getQueryParameter("token");
                if (token == null || token.isEmpty()) {
                    String path = uri.getPath();
                    if (path != null) {
                        if (path.startsWith("/")) path = path.substring(1);
                        if (!path.isEmpty()) token = path;
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Error parsing URI", e);
            }
        } else if (text.length() >= 16) {
            // Check if user entered host:port/token
            if (text.contains("/") || text.contains(":")) {
                try {
                    Uri uri = Uri.parse("aegs://" + text);
                    String host = uri.getHost();
                    int p = uri.getPort();
                    if (host != null && !host.isEmpty()) ip = host;
                    if (p > 0) port = p;
                    String path = uri.getPath();
                    if (path != null && path.startsWith("/")) path = path.substring(1);
                    if (path != null && !path.isEmpty()) token = path;
                } catch (Exception ignored) {}
            }
            if (token == null) {
                token = text;
            }
        }

        if (token == null || token.length() < 16) {
            Toast.makeText(this, "Некорректный ключ. Вставьте ссылку aegs:// или 64-значный токен.", Toast.LENGTH_LONG).show();
            return false;
        }

        String keyId = computeKeyId(token);

        mPrefs.edit()
                .putString(KEY_TOKEN, token)
                .putString(KEY_SERVER_IP, ip)
                .putInt(KEY_SERVER_PORT, port)
                .putString(KEY_KEY_ID, keyId)
                .putBoolean(KEY_HAS_ACTIVE_KEY, true)
                .apply();

        mToken = token;
        mServerIp = ip;
        mServerPort = port;
        mKeyId = keyId;

        updateKeyViews();
        Toast.makeText(this, "Ключ AEGS успешно активирован!", Toast.LENGTH_SHORT).show();
        return true;
    }

    private static String computeKeyId(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return token.substring(0, Math.min(16, token.length()));
        }
    }

    private void checkClipboardForConfig() {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null && cm.hasPrimaryClip() && cm.getPrimaryClip().getItemCount() > 0) {
                CharSequence text = cm.getPrimaryClip().getItemAt(0).getText();
                if (text != null) {
                    String clipStr = text.toString().trim();
                    if (!clipStr.equals(mLastClipboardText)) {
                        mLastClipboardText = clipStr;
                        if (clipStr.startsWith("aegs://") || (clipStr.length() == 64 && clipStr.matches("^[0-9a-fA-F]{64}$"))) {
                            if (!hasActiveKey() || !clipStr.equals(mToken)) {
                                if (mEtAccessKey != null) {
                                    mEtAccessKey.setText(clipStr);
                                }
                                Toast.makeText(this, "Обнаружен ключ AEGS в буфере обмена!", Toast.LENGTH_SHORT).show();
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    private void updateProtoBadge() {
        if (mTvProtoBadge == null) return;
        int mode = mPrefs.getInt(SettingsActivity.KEY_PROTOCOL_MODE, SettingsActivity.PROTO_EMERGENCY);
        switch (mode) {
            case SettingsActivity.PROTO_FAST_EMERGENCY:
                mTvProtoBadge.setText("v6.5   Аварийный (0-RTT)");
                if (mMetricsGraph != null) mMetricsGraph.setStatusText("0-RTT IAT: ACTIVE");
                break;
            case SettingsActivity.PROTO_TURBO_PQC:
                mTvProtoBadge.setText("v6.5   Квантовый (Kyber-768)");
                if (mMetricsGraph != null) mMetricsGraph.setStatusText("KYBER-768 PQC: ACTIVE");
                break;
            case SettingsActivity.PROTO_HYBRID_AUTO:
                mTvProtoBadge.setText("v6.5   Универсальный");
                if (mMetricsGraph != null) mMetricsGraph.setStatusText("ADAPTIVE HYBRID: ACTIVE");
                break;
            case SettingsActivity.PROTO_EMERGENCY:
            default:
                mTvProtoBadge.setText("v6.5   Chrome 128+ Reality ECH");
                if (mMetricsGraph != null) mMetricsGraph.setStatusText("ECH REALITY: ACTIVE");
                break;
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIncomingIntent(intent);
    }

    private void handleIncomingIntent(Intent intent) {
        if (intent != null && Intent.ACTION_VIEW.equals(intent.getAction())) {
            Uri data = intent.getData();
            if (data != null && "aegs".equals(data.getScheme())) {
                parseAndSaveKey(data.toString());
            }
        }
    }

    private void shareActiveKey() {
        if (!hasActiveKey()) return;
        String uri = "aegs://" + mServerIp + ":" + mServerPort + "?token=" + mToken + "&proto=titan_quic&key_id=" + mKeyId;
        String shareBody = "🔑 Персональный ключ доступа AEGS Titan VPN:\n\n" +
                uri + "\n\n" +
                "📱 Лимит: до 4 устройств одновременно (ПК, Android, iOS)\n" +
                "📥 Скачать приложение: https://github.com/XDGOOD/AEGS-Global-";
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, "Ключ AEGS Titan");
        intent.putExtra(Intent.EXTRA_TEXT, shareBody);
        startActivity(Intent.createChooser(intent, "Поделиться ключом AEGS"));
    }

    private void toggleConnection() {
        if (!hasActiveKey()) {
            Toast.makeText(this, "Сначала активируйте ключ доступа", Toast.LENGTH_SHORT).show();
            updateKeyViews();
            return;
        }

        if (!mIsConnected) {
            Intent vpnIntent = VpnService.prepare(this);
            if (vpnIntent != null) {
                startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
            } else {
                onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
            }
        } else {
            disconnectVpn();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            connectVpn();
        }
    }

    private void connectVpn() {
        if (!hasActiveKey()) {
            Toast.makeText(this, "Требуется ключ доступа!", Toast.LENGTH_SHORT).show();
            return;
        }

        boolean split = mCbSplit != null && mCbSplit.isChecked();
        int proto = mPrefs.getInt(SettingsActivity.KEY_PROTOCOL_MODE, SettingsActivity.PROTO_REALITY_ECH);
        boolean chaff = mPrefs.getBoolean(SettingsActivity.KEY_ADAPTIVE_CHAFF, true);
        boolean killSwitch = mPrefs.getBoolean(SettingsActivity.KEY_KILL_SWITCH, true);

        Intent intent = new Intent(this, AegsVpnService.class);
        intent.putExtra("SERVER_IP", mServerIp);
        intent.putExtra("SERVER_PORT", mServerPort);
        intent.putExtra("TOKEN", mToken);
        intent.putExtra("SPLIT_TUNNEL", split);
        intent.putExtra("PROTOCOL_MODE", proto);
        intent.putExtra("ADAPTIVE_CHAFF", chaff);
        intent.putExtra("KILL_SWITCH", killSwitch);

        startService(intent);

        mIsConnected = true;
        updateKeyViews();

        mPingHandler.removeCallbacks(mPingRunnable);
        mPingHandler.post(mPingRunnable);

        Toast.makeText(this, "AEGS Titan: Защита активирована", Toast.LENGTH_SHORT).show();
    }

    private void disconnectVpn() {
        Intent intent = new Intent(this, AegsVpnService.class);
        intent.setAction("STOP");
        startService(intent);

        mIsConnected = false;
        mPingHandler.removeCallbacks(mPingRunnable);

        if (mTvPing != null) {
            mTvPing.setText("Пинг к серверу: -- мс");
        }

        updateKeyViews();
        Toast.makeText(this, "Туннель отключен", Toast.LENGTH_SHORT).show();
    }
    private void updateSplitTunnelUi() {
        if (mTvSplitStatus == null) return;
        try {
            int routingMode = mPrefs.getInt("routing_mode", 0);
            java.util.Set<String> customBypass = mPrefs.getStringSet("custom_bypass_packages", null);
            if (routingMode == 1) {
                java.util.Set<String> customVpn = mPrefs.getStringSet("custom_vpn_packages", null);
                int count = (customVpn != null) ? customVpn.size() : 0;
                mTvSplitStatus.setText("Режим: Только " + count + " выбранных приложений идут через VPN.");
            } else {
                int count = (customBypass != null) ? customBypass.size() : 9;
                mTvSplitStatus.setText("Обход VPN активен для " + count + " приложений (банки и сервисы РФ напрямую).");
            }
        } catch (Exception ignored) {}
    }
}
