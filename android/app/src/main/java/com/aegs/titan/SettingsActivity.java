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
import androidx.appcompat.app.AppCompatDelegate;
import androidx.appcompat.widget.SwitchCompat;

public class SettingsActivity extends AppCompatActivity {
    public static final String PREFS_NAME = "aegs_prefs";
    public static final String KEY_PROTOCOL_MODE = "protocol_mode";
    public static final String KEY_ADAPTIVE_CHAFF = "adaptive_chaff";
    public static final String KEY_SPLIT_TUNNEL = "split_tunnel";
    public static final String KEY_KILL_SWITCH = "kill_switch";
    public static final String KEY_DYNAMIC_THEME = "dynamic_theme";

    public static final int PROTO_REALITY_ECH = 0;
    public static final int PROTO_STEALTH = 1;
    public static final int PROTO_FAST_RESUME = 2;
    public static final int PROTO_ILLUSION = 3;
    public static final int PROTO_TCP_FALLBACK = 4;

    private RadioGroup mRgProtocol;
    private SwitchCompat mSwKillSwitch;
    private SwitchCompat mSwDynamicTheme;
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
        mSwKillSwitch = findViewById(R.id.sw_killswitch);
        mSwDynamicTheme = findViewById(R.id.sw_dynamic_theme);
        mSwAdaptiveChaff = findViewById(R.id.sw_adaptive_chaff);
        mSwSplitTunnel = findViewById(R.id.sw_split_tunnel);

        // Load saved preferences
        int savedProto = mPrefs.getInt(KEY_PROTOCOL_MODE, PROTO_REALITY_ECH);
        switch (savedProto) {
            case PROTO_STEALTH:
                mRgProtocol.check(R.id.rb_proto_stealth);
                break;
            case PROTO_FAST_RESUME:
                mRgProtocol.check(R.id.rb_proto_fast_resume);
                break;
            case PROTO_ILLUSION:
                mRgProtocol.check(R.id.rb_proto_illusion);
                break;
            case PROTO_TCP_FALLBACK:
                mRgProtocol.check(R.id.rb_proto_tcp_fallback);
                break;
            case PROTO_REALITY_ECH:
            default:
                mRgProtocol.check(R.id.rb_proto_reality_ech);
                break;
        }

        mSwKillSwitch.setChecked(mPrefs.getBoolean(KEY_KILL_SWITCH, true));
        mSwDynamicTheme.setChecked(mPrefs.getBoolean(KEY_DYNAMIC_THEME, true));
        mSwAdaptiveChaff.setChecked(mPrefs.getBoolean(KEY_ADAPTIVE_CHAFF, true));
        mSwSplitTunnel.setChecked(mPrefs.getBoolean(KEY_SPLIT_TUNNEL, true));

        // Save listeners
        mRgProtocol.setOnCheckedChangeListener((group, checkedId) -> {
            int mode = PROTO_REALITY_ECH;
            if (checkedId == R.id.rb_proto_stealth) {
                mode = PROTO_STEALTH;
            } else if (checkedId == R.id.rb_proto_fast_resume) {
                mode = PROTO_FAST_RESUME;
            } else if (checkedId == R.id.rb_proto_illusion) {
                mode = PROTO_ILLUSION;
            } else if (checkedId == R.id.rb_proto_tcp_fallback) {
                mode = PROTO_TCP_FALLBACK;
            }
            mPrefs.edit().putInt(KEY_PROTOCOL_MODE, mode).apply();
            Toast.makeText(this, "Режим протокола сохранен", Toast.LENGTH_SHORT).show();
        });

        mSwKillSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            mPrefs.edit().putBoolean(KEY_KILL_SWITCH, isChecked).apply();
            Toast.makeText(this, isChecked ? "Kill-Switch активирован" : "Kill-Switch отключен", Toast.LENGTH_SHORT).show();
        });

        mSwDynamicTheme.setOnCheckedChangeListener((buttonView, isChecked) -> {
            mPrefs.edit().putBoolean(KEY_DYNAMIC_THEME, isChecked).apply();
            if (isChecked) {
                AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM);
            } else {
                AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES);
            }
        });

        mSwAdaptiveChaff.setOnCheckedChangeListener((buttonView, isChecked) -> {
            mPrefs.edit().putBoolean(KEY_ADAPTIVE_CHAFF, isChecked).apply();
        });

        mSwSplitTunnel.setOnCheckedChangeListener((buttonView, isChecked) -> {
            mPrefs.edit().putBoolean(KEY_SPLIT_TUNNEL, isChecked).apply();
        });

        // Author and GitHub links
        View btnAuthor = findViewById(R.id.btn_link_author);
        if (btnAuthor != null) {
            btnAuthor.setOnClickListener(v -> openUrl("https://github.com/XDGOOD"));
        }

        View btnCore = findViewById(R.id.btn_link_core);
        if (btnCore != null) {
            btnCore.setOnClickListener(v -> openUrl("https://github.com/XDGOOD/net-packet-handler"));
        }

        View btnGlobal = findViewById(R.id.btn_link_global);
        if (btnGlobal != null) {
            btnGlobal.setOnClickListener(v -> openUrl("https://github.com/XDGOOD/AEGS-Global-"));
        }
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
