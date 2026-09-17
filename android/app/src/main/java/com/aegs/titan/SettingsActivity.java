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

        View btnLicense = findViewById(R.id.btn_link_license);
        if (btnLicense != null) {
            btnLicense.setOnClickListener(v -> showLicenseDialog());
        }

        View btnChooseBypass = findViewById(R.id.btn_choose_bypass_apps);
        if (btnChooseBypass != null) {
            btnChooseBypass.setOnClickListener(v -> showAppSelectionDialog());
        }
        updateBypassCountLabel();
    }

    private void openUrl(String url) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(this, "Не удалось открыть ссылку: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void updateBypassCountLabel() {
        android.widget.TextView tv = findViewById(R.id.tv_bypass_apps_count);
        if (tv == null) return;
        java.util.Set<String> custom = mPrefs.getStringSet("custom_bypass_packages", null);
        int count = custom != null ? custom.size() : 9; // 9 default banking/gov apps
        tv.setText("Приложения в обход туннеля (" + count + " выбрано)");
    }

    private void showLicenseDialog() {
        new androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("AEGS Non-Commercial Community License v1.0")
                .setMessage("Правообладатель и автор протокола: XDGOOD\n\n" +
                        "Протокол AEGS и мобильный клиент распространяются исключительно для некоммерческого, исследовательского и личного использования.\n\n" +
                        "⚠️ Любое коммерческое использование, перепродажа, продажа платных VPN-подписок и интеграция в коммерческие маршрутизаторы без прямого предварительного письменного согласия автора (XDGOOD) СТРОГО ЗАПРЕЩЕНЫ.\n\n" +
                        "Все права защищены.")
                .setPositiveButton("Понятно", null)
                .show();
    }

    private void showAppSelectionDialog() {
        new Thread(() -> {
            PackageManager pm = getPackageManager();
            java.util.List<android.content.pm.ApplicationInfo> installed = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            java.util.List<String> names = new java.util.ArrayList<>();
            java.util.List<String> pkgs = new java.util.ArrayList<>();

            for (android.content.pm.ApplicationInfo ai : installed) {
                if ((ai.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 || pm.getLaunchIntentForPackage(ai.packageName) != null) {
                    names.add(pm.getApplicationLabel(ai).toString() + " (" + ai.packageName + ")");
                    pkgs.add(ai.packageName);
                }
            }

            java.util.Set<String> saved = mPrefs.getStringSet("custom_bypass_packages", null);
            if (saved == null) {
                saved = new java.util.HashSet<>(java.util.Arrays.asList(
                        "ru.sberbankmobile", "com.idamob.tinkoff.android", "ru.vtb24.mobilebanking",
                        "ru.alfabank.mobile.android", "ru.gosuslugi.net", "ru.yandex.searchplugin",
                        "com.vkontakte.android", "ru.ozon.app.android", "com.wildberries.ru"
                ));
            }

            final boolean[] checked = new boolean[pkgs.size()];
            for (int i = 0; i < pkgs.size(); i++) {
                checked[i] = saved.contains(pkgs.get(i));
            }

            runOnUiThread(() -> {
                new androidx.appcompat.app.AlertDialog.Builder(this)
                        .setTitle("Приложения в обход VPN")
                        .setMultiChoiceItems(names.toArray(new CharSequence[0]), checked, (dialog, which, isChecked) -> {
                            checked[which] = isChecked;
                        })
                        .setPositiveButton("Сохранить", (dialog, which) -> {
                            java.util.Set<String> newSet = new java.util.HashSet<>();
                            for (int i = 0; i < pkgs.size(); i++) {
                                if (checked[i]) newSet.add(pkgs.get(i));
                            }
                            mPrefs.edit().putStringSet("custom_bypass_packages", newSet).apply();
                            updateBypassCountLabel();
                            Toast.makeText(this, "Сохранено приложений в обход: " + newSet.size(), Toast.LENGTH_SHORT).show();
                        })
                        .setNegativeButton("Отмена", null)
                        .show();
            });
        }).start();
    }
}
