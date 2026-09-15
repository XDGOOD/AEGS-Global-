package com.aegs.titan;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.RadioGroup;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

public class SettingsActivity extends AppCompatActivity {
    public static final String PREFS_NAME = "aegs_prefs";
    public static final String KEY_PROTOCOL_MODE = "protocol_mode";
    public static final String KEY_ADAPTIVE_CHAFF = "adaptive_chaff";
    public static final String KEY_SPLIT_TUNNEL = "split_tunnel";

    public static final int PROTO_STEALTH = 0;
    public static final int PROTO_FAST_RESUME = 1;
    public static final int PROTO_ILLUSION = 2;
    public static final int PROTO_TCP_FALLBACK = 3;

    private RadioGroup mRgProtocol;
    private SwitchCompat mSwAdaptiveChaff;
    private SwitchCompat mSwSplitTunnel;
    private SharedPreferences mPrefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        mPrefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

        ImageView btnBack = findViewById(R.id.btn_back);
        btnBack.setOnClickListener(v -> finish());

        mRgProtocol = findViewById(R.id.rg_protocol);
        mSwAdaptiveChaff = findViewById(R.id.sw_adaptive_chaff);
        mSwSplitTunnel = findViewById(R.id.sw_split_tunnel);

        // Load saved preferences
        int savedProto = mPrefs.getInt(KEY_PROTOCOL_MODE, PROTO_STEALTH);
        switch (savedProto) {
            case PROTO_FAST_RESUME:
                mRgProtocol.check(R.id.rb_proto_fast_resume);
                break;
            case PROTO_ILLUSION:
                mRgProtocol.check(R.id.rb_proto_illusion);
                break;
            case PROTO_TCP_FALLBACK:
                mRgProtocol.check(R.id.rb_proto_tcp_fallback);
                break;
            case PROTO_STEALTH:
            default:
                mRgProtocol.check(R.id.rb_proto_stealth);
                break;
        }

        mSwAdaptiveChaff.setChecked(mPrefs.getBoolean(KEY_ADAPTIVE_CHAFF, true));
        mSwSplitTunnel.setChecked(mPrefs.getBoolean(KEY_SPLIT_TUNNEL, true));

        // Save listeners
        mRgProtocol.setOnCheckedChangeListener((group, checkedId) -> {
            int mode = PROTO_STEALTH;
            if (checkedId == R.id.rb_proto_fast_resume) {
                mode = PROTO_FAST_RESUME;
            } else if (checkedId == R.id.rb_proto_illusion) {
                mode = PROTO_ILLUSION;
            } else if (checkedId == R.id.rb_proto_tcp_fallback) {
                mode = PROTO_TCP_FALLBACK;
            }
            mPrefs.edit().putInt(KEY_PROTOCOL_MODE, mode).apply();
            Toast.makeText(this, "Режим протокола обновлен", Toast.LENGTH_SHORT).show();
        });

        mSwAdaptiveChaff.setOnCheckedChangeListener((buttonView, isChecked) -> {
            mPrefs.edit().putBoolean(KEY_ADAPTIVE_CHAFF, isChecked).apply();
        });

        mSwSplitTunnel.setOnCheckedChangeListener((buttonView, isChecked) -> {
            mPrefs.edit().putBoolean(KEY_SPLIT_TUNNEL, isChecked).apply();
        });

        // GitHub links
        View btnCore = findViewById(R.id.btn_link_core);
        btnCore.setOnClickListener(v -> openUrl("https://github.com/XDGOOD/net-packet-handler"));

        View btnGlobal = findViewById(R.id.btn_link_global);
        btnGlobal.setOnClickListener(v -> openUrl("https://github.com/XDGOOD/AEGS-Global-"));
    }

    private void openUrl(String url) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(this, "Не удалось открыть ссылку: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }
}
