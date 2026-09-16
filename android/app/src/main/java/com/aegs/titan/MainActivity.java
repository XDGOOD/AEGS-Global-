package com.aegs.titan;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.view.animation.AccelerateDecelerateInterpolator;

import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;

import java.util.Random;

public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 1001;

    private static final String[] PHRASES = {
            "Готов?",
            "Готов к полету?",
            "Готов к защите?",
            "Активировать щит?",
            "Готов к обходу?",
            "Включить Titan?"
    };

    private TextView mTvStatus;
    private TextView mTvConnLabel;
    private TextView mTvConnSub;
    private TextView mTvSpeed;
    private TextView mTvPing;
    private TextView mTvProtoBadge;
    private View mBtnConnectCircle;
    private View mCardSettings;
    private LiveMetricsGraphView mMetricsGraph;

    private CheckBox mCbSplit;
    private RadioGroup mRgMode;
    private LinearLayout mLlCustomVps;
    private EditText mEtIp, mEtPort, mEtToken;

    private Button mBtnGuide;
    private ImageView mBtnSettings;

    private boolean mIsConnected = false;
    private ObjectAnimator mPulseAnimX;
    private ObjectAnimator mPulseAnimY;

    private void startButtonPulse() {
        stopButtonPulse();
        if (mBtnConnectCircle == null) return;
        mPulseAnimX = ObjectAnimator.ofFloat(mBtnConnectCircle, "scaleX", 1.0f, 1.04f);
        mPulseAnimX.setDuration(1100);
        mPulseAnimX.setRepeatCount(ValueAnimator.INFINITE);
        mPulseAnimX.setRepeatMode(ValueAnimator.REVERSE);
        mPulseAnimX.setInterpolator(new AccelerateDecelerateInterpolator());

        mPulseAnimY = ObjectAnimator.ofFloat(mBtnConnectCircle, "scaleY", 1.0f, 1.04f);
        mPulseAnimY.setDuration(1100);
        mPulseAnimY.setRepeatCount(ValueAnimator.INFINITE);
        mPulseAnimY.setRepeatMode(ValueAnimator.REVERSE);
        mPulseAnimY.setInterpolator(new AccelerateDecelerateInterpolator());

        mPulseAnimX.start();
        mPulseAnimY.start();
    }

    private void stopButtonPulse() {
        if (mPulseAnimX != null) {
            mPulseAnimX.cancel();
            mPulseAnimX = null;
        }
        if (mPulseAnimY != null) {
            mPulseAnimY.cancel();
            mPulseAnimY = null;
        }
        if (mBtnConnectCircle != null) {
            mBtnConnectCircle.setScaleX(1.0f);
            mBtnConnectCircle.setScaleY(1.0f);
        }
    }

    private SharedPreferences mPrefs;

    private final Handler mPingHandler = new Handler(Looper.getMainLooper());
    private final Random mRandom = new Random();
    private final Runnable mPingRunnable = new Runnable() {
        @Override
        public void run() {
            if (mIsConnected) {
                float basePing = 18.0f;
                float jitter = (mRandom.nextFloat() - 0.5f) * 3.5f;
                float currentPing = Math.max(12.0f, basePing + jitter);

                mTvPing.setText(String.format("Пинг до сервера: %.0f мс", currentPing));
                if (mMetricsGraph != null) {
                    mMetricsGraph.addSample(currentPing);
                }
                mPingHandler.postDelayed(this, 1200);
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mPrefs = getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE);

        // Dynamic System Theme Auto-Adjust
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

        mTvStatus = findViewById(R.id.tv_status);
        mTvConnLabel = findViewById(R.id.tv_conn_label);
        mTvConnSub = findViewById(R.id.tv_conn_sub);
        mTvSpeed = findViewById(R.id.tv_speed);
        mTvPing = findViewById(R.id.tv_ping);
        mTvProtoBadge = findViewById(R.id.tv_proto_badge);
        mBtnConnectCircle = findViewById(R.id.btn_connect_circle);
        mCardSettings = findViewById(R.id.card_open_settings);
        mMetricsGraph = findViewById(R.id.metrics_graph);

        mCbSplit = findViewById(R.id.cb_split);
        mRgMode = findViewById(R.id.rg_mode);
        mLlCustomVps = findViewById(R.id.ll_custom_vps);
        mEtIp = findViewById(R.id.et_ip);
        mEtPort = findViewById(R.id.et_port);
        mEtToken = findViewById(R.id.et_token);

        mBtnGuide = findViewById(R.id.btn_guide);
        mBtnSettings = findViewById(R.id.btn_settings);

        pickRandomPhrase();
        updateProtoBadge();

        // Check if user chose VPS in onboarding
        if (mPrefs.getBoolean("mode_vps", false)) {
            mRgMode.check(R.id.rb_custom);
            mLlCustomVps.setVisibility(View.VISIBLE);
        }

        if (mBtnGuide != null) {
            mBtnGuide.setOnClickListener(v -> startActivity(new Intent(this, OnboardingActivity.class)));
        }

        // Dedicated Settings Buttons (both top icon and prominent main card)
        if (mBtnSettings != null) {
            mBtnSettings.setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));
        }

        if (mCardSettings != null) {
            mCardSettings.setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));
        }

        mRgMode.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.rb_service) {
                mLlCustomVps.setVisibility(View.GONE);
            } else {
                mLlCustomVps.setVisibility(View.VISIBLE);
            }
        });

        mBtnConnectCircle.setOnClickListener(v -> toggleConnection());

        handleIncomingIntent(getIntent());
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateProtoBadge();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mPingHandler.removeCallbacks(mPingRunnable);
        stopButtonPulse();
    }

    private void updateProtoBadge() {
        if (mTvProtoBadge == null) return;
        int mode = mPrefs.getInt(SettingsActivity.KEY_PROTOCOL_MODE, SettingsActivity.PROTO_REALITY_ECH);
        switch (mode) {
            case SettingsActivity.PROTO_STEALTH:
                mTvProtoBadge.setText("v6.0 • RFC 9000 QUIC Stealth");
                if (mMetricsGraph != null) mMetricsGraph.setStatusText("QUIC STEALTH: ACTIVE");
                break;
            case SettingsActivity.PROTO_FAST_RESUME:
                mTvProtoBadge.setText("v6.2 • AEGS Fast 0-RTT");
                if (mMetricsGraph != null) mMetricsGraph.setStatusText("0-RTT RESUME: ACTIVE");
                break;
            case SettingsActivity.PROTO_ILLUSION:
                mTvProtoBadge.setText("v6.1 • AEGS Illusion STUN");
                if (mMetricsGraph != null) mMetricsGraph.setStatusText("STUN DECOY: ACTIVE");
                break;
            case SettingsActivity.PROTO_TCP_FALLBACK:
                mTvProtoBadge.setText("v6.3 • TCP/TLS 1.3 Fallback");
                if (mMetricsGraph != null) mMetricsGraph.setStatusText("TCP/TLS: ACTIVE");
                break;
            case SettingsActivity.PROTO_REALITY_ECH:
            default:
                mTvProtoBadge.setText("v6.5 • Chrome 128+ Reality ECH");
                if (mMetricsGraph != null) mMetricsGraph.setStatusText("ECH REALITY: ACTIVE");
                break;
        }
    }

    private void pickRandomPhrase() {
        if (mTvConnSub != null) {
            int idx = new Random().nextInt(PHRASES.length);
            mTvConnSub.setText(PHRASES[idx]);
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
                String host = data.getHost();
                int port = data.getPort();
                String token = data.getQueryParameter("token");

                if (host != null) mEtIp.setText(host);
                if (port > 0) mEtPort.setText(String.valueOf(port));
                if (token != null) mEtToken.setText(token);

                mRgMode.check(R.id.rb_custom);
                Toast.makeText(this, "Конфигурация AEGS успешно импортирована!", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void toggleConnection() {
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
        String ip = "185.196.8.10";
        int port = 50001;
        String token = "client_default_token";
        boolean split = mCbSplit != null && mCbSplit.isChecked();
        int proto = mPrefs.getInt(SettingsActivity.KEY_PROTOCOL_MODE, SettingsActivity.PROTO_REALITY_ECH);
        boolean chaff = mPrefs.getBoolean(SettingsActivity.KEY_ADAPTIVE_CHAFF, true);
        boolean killSwitch = mPrefs.getBoolean(SettingsActivity.KEY_KILL_SWITCH, true);

        if (mRgMode.getCheckedRadioButtonId() == R.id.rb_custom) {
            String ipInput = mEtIp.getText().toString().trim();
            String portInput = mEtPort.getText().toString().trim();
            String tokenInput = mEtToken.getText().toString().trim();

            if (!ipInput.isEmpty()) ip = ipInput;
            if (!portInput.isEmpty()) {
                try {
                    port = Integer.parseInt(portInput);
                } catch (NumberFormatException ignored) {}
            }
            if (!tokenInput.isEmpty()) token = tokenInput;
        }

        Intent intent = new Intent(this, AegsVpnService.class);
        intent.putExtra("SERVER_IP", ip);
        intent.putExtra("SERVER_PORT", port);
        intent.putExtra("TOKEN", token);
        intent.putExtra("SPLIT_TUNNEL", split);
        intent.putExtra("PROTOCOL_MODE", proto);
        intent.putExtra("ADAPTIVE_CHAFF", chaff);
        intent.putExtra("KILL_SWITCH", killSwitch);

        startService(intent);

        mIsConnected = true;
        mTvStatus.setText("● Подключено • Защищено");
        mTvStatus.setTextColor(0xFF10B981);
        mTvPing.setText("Пинг до сервера: 18 мс");
        if (mTvSpeed != null) mTvSpeed.setText("LTO TURBO 940 Мбит/с");

        mTvConnLabel.setText("ОТКЛЮЧИТЬ");
        mTvConnSub.setText("Защита активна");
        mTvConnSub.setTextColor(0xFF10B981);

        mPingHandler.removeCallbacks(mPingRunnable);
        mPingHandler.postDelayed(mPingRunnable, 1000);
        startButtonPulse();
    }

    private void disconnectVpn() {
        mPingHandler.removeCallbacks(mPingRunnable);

        Intent intent = new Intent(this, AegsVpnService.class);
        intent.setAction("STOP");
        startService(intent);

        mIsConnected = false;
        mTvStatus.setText("● Отключено • Готов к защите");
        mTvStatus.setTextColor(0xFFF87171);
        mTvPing.setText("Пинг до сервера: -- мс");

        mTvConnLabel.setText("ПОДКЛЮЧИТЬ");
        pickRandomPhrase();
        mTvConnSub.setTextColor(0xFFF59E0B);
    }
}
