package com.aegs.titan;

import android.content.Intent;
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
    private Button mBtnConnect;
    private RadioGroup mRgMode;
    private View mLlCustomVps;
    private EditText mEtIp;
    private EditText mEtPort;
    private EditText mEtToken;
    private CheckBox mCbSplit;

    private boolean mIsConnected = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mTvStatus = findViewById(R.id.tv_status);
        mTvPing = findViewById(R.id.tv_ping);
        mBtnConnect = findViewById(R.id.btn_connect);
        mRgMode = findViewById(R.id.rg_mode);
        mLlCustomVps = findViewById(R.id.ll_custom_vps);
        mEtIp = findViewById(R.id.et_ip);
        mEtPort = findViewById(R.id.et_port);
        mEtToken = findViewById(R.id.et_token);
        mCbSplit = findViewById(R.id.cb_split);

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
            startVpn();
        }
    }

    private void startVpn() {
        String ip = "185.196.8.10";
        int port = 50001;
        String token = "aegs_secure_token_titan_v6";

        if (mRgMode.getCheckedRadioButtonId() == R.id.rb_custom) {
            ip = mEtIp.getText().toString().trim();
            try {
                port = Integer.parseInt(mEtPort.getText().toString().trim());
            } catch (Exception ignored) {}
            token = mEtToken.getText().toString().trim();
        }

        Intent intent = new Intent(this, AegsVpnService.class);
        intent.putExtra("SERVER_IP", ip);
        intent.putExtra("SERVER_PORT", port);
        intent.putExtra("TOKEN", token);
        intent.putExtra("SPLIT_TUNNEL", mCbSplit.isChecked());
        startService(intent);

        mIsConnected = true;
        mTvStatus.setText("● Подключено (AEGS v6.5 Stealth)");
        mTvStatus.setTextColor(0xFF00D26A);
        mTvPing.setText("Пинг: 22 мс");
        mBtnConnect.setText("ОТКЛЮЧИТЬСЯ");
        mBtnConnect.setBackgroundColor(0xFFDC3545);
    }

    private void disconnectVpn() {
        Intent intent = new Intent(this, AegsVpnService.class);
        intent.setAction("STOP");
        startService(intent);

        mIsConnected = false;
        mTvStatus.setText("● Отключено");
        mTvStatus.setTextColor(0xFFF87171);
        mTvPing.setText("Пинг: -- мс");
        mBtnConnect.setText("ПОДКЛЮЧИТЬСЯ");
        mBtnConnect.setBackgroundColor(0xFF0D6EFD);
    }
}
