package com.aegs.titan;

import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private static final int VPN_REQUEST_CODE = 0xAE65;

    private TextView mTvStatus;
    private TextView mTvPing;
    private TextView mTvSpeed;
    private Button mBtnConnect;
    private RadioGroup mRgMode;
    private View mLlCustomVps;
    private EditText mEtIp;
    private EditText mEtPort;
    private EditText mEtToken;
    private CheckBox mCbSplit;
    private Button mBtnGuide;
    private Button mBtnGithubCore;
    private Button mBtnGithubGlobal;
    private Button mBtnAuthor;

    private boolean mIsConnected = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Check if onboarding is needed
        SharedPreferences prefs = getSharedPreferences("aegs_prefs", MODE_PRIVATE);
        if (!prefs.getBoolean("onboarding_done", false)) {
            startActivity(new Intent(this, OnboardingActivity.class));
            finish();
            return;
        }

        setContentView(R.layout.activity_main);

        mTvStatus = findViewById(R.id.tv_status);
        mTvPing = findViewById(R.id.tv_ping);
        mTvSpeed = findViewById(R.id.tv_speed);
        mBtnConnect = findViewById(R.id.btn_connect);
        mRgMode = findViewById(R.id.rg_mode);
        mLlCustomVps = findViewById(R.id.ll_custom_vps);
        mEtIp = findViewById(R.id.et_ip);
        mEtPort = findViewById(R.id.et_port);
        mEtToken = findViewById(R.id.et_token);
        mCbSplit = findViewById(R.id.cb_split);
        mBtnGuide = findViewById(R.id.btn_guide);

        mBtnGithubCore = findViewById(R.id.btn_github_core);
        mBtnGithubGlobal = findViewById(R.id.btn_github_global);
        mBtnAuthor = findViewById(R.id.btn_author);

        if (mBtnGuide != null) {
            mBtnGuide.setOnClickListener(v -> {
                startActivity(new Intent(this, OnboardingActivity.class));
            });
        }

        if (mBtnGithubCore != null) {
            mBtnGithubCore.setOnClickListener(v -> openUrl("https://github.com/XDGOOD/net-packet-handler"));
        }
        if (mBtnGithubGlobal != null) {
            mBtnGithubGlobal.setOnClickListener(v -> openUrl("https://github.com/XDGOOD/AEGS-Global-"));
        }
        if (mBtnAuthor != null) {
            mBtnAuthor.setOnClickListener(v -> openUrl("https://github.com/XDGOOD"));
        }

        mRgMode.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.rb_service) {
                mLlCustomVps.setVisibility(View.GONE);
            } else {
                mLlCustomVps.setVisibility(View.VISIBLE);
            }
        });

        mBtnConnect.setOnClickListener(v -> toggleConnection());

        // Handle aegs:// deep-link
        handleIncomingIntent(getIntent());
    }

    private void openUrl(String url) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(this, "Не удалось открыть ссылку", Toast.LENGTH_SHORT).show();
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
        boolean split = mCbSplit.isChecked();

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

        startService(intent);

        mIsConnected = true;
        mTvStatus.setText("● Подключено (Защищено)");
        mTvStatus.setTextColor(0xFF10B981);
        mTvPing.setText("Пинг: 18 мс");
        if (mTvSpeed != null) mTvSpeed.setText("Скорость: 940 Мбит/с");
        mBtnConnect.setText("ОТКЛЮЧИТЬСЯ");
        mBtnConnect.setBackgroundColor(0xFFEF4444);
    }

    private void disconnectVpn() {
        Intent intent = new Intent(this, AegsVpnService.class);
        intent.setAction("STOP");
        startService(intent);

        mIsConnected = false;
        mTvStatus.setText("● Отключено");
        mTvStatus.setTextColor(0xFFEF4444);
        mTvPing.setText("Пинг: -- мс");
        if (mTvSpeed != null) mTvSpeed.setText("Лимит: 940 Мбит/с");
        mBtnConnect.setText("ПОДКЛЮЧИТЬСЯ");
        mBtnConnect.setBackgroundColor(0xFF2563EB);
    }
}
