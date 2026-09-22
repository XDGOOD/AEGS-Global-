package com.aegs.titan;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * AppRoutingActivity - Per-App Split-Tunneling and Smart Russian Services Routing.
 * Analyzes installed applications on Android, detects Russian services (banking,
 * Gosuslugi, delivery, marketplaces, telecoms, media), and provides 1-click
 * automatic bypass to prevent geo-blocking on domestic services.
 */
public class AppRoutingActivity extends AppCompatActivity {

    public static class AppInfo implements Comparable<AppInfo> {
        public String packageName;
        public String label;
        public Drawable icon;
        public boolean isDirect;   // true = direct bypass (no VPN), false = routed via VPN
        public boolean isRussian;  // true = Russian banking/gov/delivery/e-commerce service

        @Override
        public int compareTo(AppInfo o) {
            if (this.isRussian != o.isRussian) {
                return this.isRussian ? -1 : 1; // Russian services first
            }
            return this.label.compareToIgnoreCase(o.label);
        }
    }

    // Comprehensive registry of Russian critical services
    private static final Set<String> RU_KNOWN_PACKAGES = new HashSet<>(Arrays.asList(
            // Banks & Fintech
            "ru.sberbankmobile", "com.idamob.tinkoff.android", "ru.vtb24.mobilebanking",
            "ru.alfabank.mobile.android", "ru.raiffeisennews", "ru.gazprombank.android.mobilebank",
            "ru.sovcomcard.halva.v1", "ru.open.bronarm", "ru.rosbank.android",
            "ru.psbank.mobile.android", "ru.mts.bank", "ru.yoomoney", "ru.nspk.mirpay",
            "ru.ozon.fintech", "ru.bpc.mobilebanking.bspb", "ru.rshb.dbo",
            "ru.homecredit.mycredit", "ru.unicredit.unicreditrustelebank", "ru.uralsib.mb",
            "ru.akbars.mobile", "ru.rencredit.mobilebank", "ru.sovcombank.info",

            // Government & Public Services
            "ru.gosuslugi.net", "ru.gosuslugi.auto", "ru.fns.billtax", "ru.fns.taxpayerfl",
            "ru.russianpost.android", "ru.mos.app", "ru.emias.app", "ru.rostelecom.digitaltv",
            "ru.spb.ias.parkings", "ru.gibdd.app", "ru.fssprus.fssprussia",

            // Marketplaces, E-Commerce & Delivery
            "ru.ozon.app.android", "com.wildberries.ru", "ru.yandex.market", "com.sbermarket",
            "ru.samokat", "ru.avito", "ru.vseinstrumenti.shop", "ru.dns.shop",
            "ru.mvideo.b2c", "ru.eldorado.app", "ru.magnit.app", "ru.perekrestok.app",
            "ru.pyaterochka.app", "com.deliveryclub", "ru.dostavista.client", "ru.cdek.cdek_app",
            "ru.kuper.app", "ru.leroymerlin.mobile",

            // Yandex Ecosystem
            "ru.yandex.searchplugin", "ru.yandex.yandexnavi", "ru.yandex.yandexmaps",
            "ru.yandex.taxi", "ru.yandex.music", "ru.yandex.disk", "ru.yandex.weatherplugin",
            "ru.kinopoisk", "ru.yandex.browser", "ru.yandex.go", "ru.yandex.kinopoisk",
            "com.yandex.browser", "ru.yandex.mail", "ru.yandex.eda",

            // VK & Mail.ru Ecosystem & Social
            "com.vkontakte.android", "com.vk.im", "com.vk.calls", "ru.mail.mailapp",
            "ru.mail.cloud", "ru.ok.android", "ru.rutube.app", "ru.zen.android",
            "com.my.games.store", "ru.vk.store",

            // Streaming & Media
            "ru.ivi.client", "ru.okko.tv", "premier.one", "ru.kion", "ru.wink",
            "ru.more.play", "ru.start.android", "ru.smotrim.app", "ru.ntv.client",

            // Telecom & Cellular Operators
            "ru.mts.mymts", "ru.megafon.mlk", "ru.beeline.services", "ru.tele2.mytele2",
            "com.yota.user", "ru.rostelecom.lk", "ru.tinkoff.mobile"
    ));

    private SharedPreferences mPrefs;
    private final Set<String> mBypassPackages = new HashSet<>();
    private final Set<String> mVpnPackages = new HashSet<>();

    private final List<AppInfo> mAllApps = new ArrayList<>();
    private final List<AppInfo> mDisplayedApps = new ArrayList<>();

    private AppAdapter mAdapter;
    private ProgressBar mProgressBar;
    private ListView mListView;
    private TextView mTvSubtitle;

    // Smart Analysis Card
    private View mCardSmartAnalysis;
    private TextView mTvSmartTitle;
    private TextView mTvSmartDesc;
    private TextView mBtnApplySmartRu;

    // Routing Mode
    private RadioGroup mRgRoutingMode;
    private RadioButton mRbModeBypass;
    private RadioButton mRbModeVpnOnly;
    private int mRoutingMode = 0; // 0 = Bypass selected, 1 = VPN only for selected

    // Search and Filters
    private EditText mEtSearch;
    private TextView mBtnFilterAll;
    private TextView mBtnFilterVpn;
    private TextView mBtnFilterDirect;
    private TextView mBtnFilterRu;
    private int mCurrentFilter = 0; // 0 = All, 1 = VPN, 2 = Direct, 3 = Russian

    // Quick Batch Action Buttons
    private TextView mBtnQuickAllVpn;
    private TextView mBtnQuickAllDirect;
    private TextView mBtnQuickSelectRu;

    private int mDetectedRuCount = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_routing);

        mPrefs = getSharedPreferences("aegs_prefs", Context.MODE_PRIVATE);
        mRoutingMode = mPrefs.getInt("routing_mode", 0);

        initViews();
        setupRoutingMode();
        setupFilters();
        setupQuickActions();
        setupSearch();

        mAdapter = new AppAdapter();
        mListView.setAdapter(mAdapter);

        loadInstalledApps();
    }

    private void initViews() {
        ImageView btnBack = findViewById(R.id.btn_back_routing);
        if (btnBack != null) {
            btnBack.setOnClickListener(v -> finish());
        }

        mTvSubtitle = findViewById(R.id.tv_routing_subtitle);
        mProgressBar = findViewById(R.id.pb_loading_apps);
        mListView = findViewById(R.id.lv_apps);

        mCardSmartAnalysis = findViewById(R.id.card_smart_analysis);
        mTvSmartTitle = findViewById(R.id.tv_smart_analysis_title);
        mTvSmartDesc = findViewById(R.id.tv_smart_analysis_desc);
        mBtnApplySmartRu = findViewById(R.id.btn_apply_smart_ru);

        mRgRoutingMode = findViewById(R.id.rg_routing_mode);
        mRbModeBypass = findViewById(R.id.rb_mode_bypass);
        mRbModeVpnOnly = findViewById(R.id.rb_mode_vpn_only);

        mEtSearch = findViewById(R.id.et_search_apps);

        mBtnFilterAll = findViewById(R.id.btn_filter_all);
        mBtnFilterVpn = findViewById(R.id.btn_filter_vpn);
        mBtnFilterDirect = findViewById(R.id.btn_filter_direct);
        mBtnFilterRu = findViewById(R.id.btn_filter_ru);

        mBtnQuickAllVpn = findViewById(R.id.btn_quick_all_vpn);
        mBtnQuickAllDirect = findViewById(R.id.btn_quick_all_direct);
        mBtnQuickSelectRu = findViewById(R.id.btn_quick_select_ru);
    }

    private void setupRoutingMode() {
        if (mRgRoutingMode != null) {
            if (mRoutingMode == 1 && mRbModeVpnOnly != null) {
                mRbModeVpnOnly.setChecked(true);
            } else if (mRbModeBypass != null) {
                mRbModeBypass.setChecked(true);
            }

            mRgRoutingMode.setOnCheckedChangeListener((group, checkedId) -> {
                mRoutingMode = (checkedId == R.id.rb_mode_vpn_only) ? 1 : 0;
                mPrefs.edit().putInt("routing_mode", mRoutingMode).apply();
                applyQueryAndFilter();
                String modeName = (mRoutingMode == 1)
                        ? "Режим: Только выбранные приложения идут через VPN"
                        : "Режим: Выбранные приложения в обход VPN (прямое соединение)";
                Toast.makeText(this, modeName, Toast.LENGTH_SHORT).show();
            });
        }
    }

    private void setupFilters() {
        if (mBtnFilterAll != null) mBtnFilterAll.setOnClickListener(v -> setFilter(0));
        if (mBtnFilterVpn != null) mBtnFilterVpn.setOnClickListener(v -> setFilter(1));
        if (mBtnFilterDirect != null) mBtnFilterDirect.setOnClickListener(v -> setFilter(2));
        if (mBtnFilterRu != null) mBtnFilterRu.setOnClickListener(v -> setFilter(3));
    }

    private void setFilter(int filterMode) {
        mCurrentFilter = filterMode;

        updateFilterTab(mBtnFilterAll, filterMode == 0, Color.parseColor("#18181B"), Color.parseColor("#A8A29E"));
        updateFilterTab(mBtnFilterVpn, filterMode == 1, Color.parseColor("#18181B"), Color.parseColor("#A8A29E"));
        updateFilterTab(mBtnFilterDirect, filterMode == 2, Color.parseColor("#18181B"), Color.parseColor("#A8A29E"));
        updateFilterTab(mBtnFilterRu, filterMode == 3, Color.parseColor("#18181B"), Color.parseColor("#F59E0B"));

        applyQueryAndFilter();
    }

    private void updateFilterTab(TextView btn, boolean active, int activeTextColor, int inactiveTextColor) {
        if (btn == null) return;
        if (active) {
            btn.setBackgroundResource(R.drawable.btn_amber_gradient);
            btn.setTextColor(activeTextColor);
        } else {
            btn.setBackgroundResource(R.drawable.card_obsidian);
            btn.setTextColor(inactiveTextColor);
        }
    }

    private void setupQuickActions() {
        if (mBtnQuickAllVpn != null) {
            mBtnQuickAllVpn.setOnClickListener(v -> {
                for (AppInfo a : mAllApps) {
                    a.isDirect = false;
                    mBypassPackages.remove(a.packageName);
                    mVpnPackages.add(a.packageName);
                }
                savePreferences();
                applyQueryAndFilter();
                Toast.makeText(this, "Все приложения направлены через VPN!", Toast.LENGTH_SHORT).show();
            });
        }

        if (mBtnQuickAllDirect != null) {
            mBtnQuickAllDirect.setOnClickListener(v -> {
                for (AppInfo a : mAllApps) {
                    a.isDirect = true;
                    mBypassPackages.add(a.packageName);
                    mVpnPackages.remove(a.packageName);
                }
                savePreferences();
                applyQueryAndFilter();
                Toast.makeText(this, "Все приложения пущены напрямую в обход VPN!", Toast.LENGTH_SHORT).show();
            });
        }

        if (mBtnQuickSelectRu != null) {
            mBtnQuickSelectRu.setOnClickListener(v -> applyRussianDirectPreset());
        }

        if (mBtnApplySmartRu != null) {
            mBtnApplySmartRu.setOnClickListener(v -> applyRussianDirectPreset());
        }
    }

    private void applyRussianDirectPreset() {
        int count = 0;
        for (AppInfo a : mAllApps) {
            if (a.isRussian) {
                a.isDirect = true;
                mBypassPackages.add(a.packageName);
                mVpnPackages.remove(a.packageName);
                count++;
            }
        }
        savePreferences();
        applyQueryAndFilter();

        if (mBtnApplySmartRu != null) {
            mBtnApplySmartRu.setText("✓ " + count + " сервисов РФ настроены в обход VPN");
        }
        Toast.makeText(this, "⚡ " + count + " сервисов РФ переведены в обход VPN (банки, Госуслуги, доставка)", Toast.LENGTH_LONG).show();
    }

    private void setupSearch() {
        if (mEtSearch != null) {
            mEtSearch.addTextChangedListener(new TextWatcher() {
                @Override
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

                @Override
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                    applyQueryAndFilter();
                }

                @Override
                public void afterTextChanged(Editable s) {}
            });
        }
    }

    private void loadInstalledApps() {
        new Thread(() -> {
            PackageManager pm = getPackageManager();
            List<ApplicationInfo> installed = pm.getInstalledApplications(PackageManager.GET_META_DATA);

            Set<String> savedBypass = mPrefs.getStringSet("custom_bypass_packages", null);
            boolean isFirstRun = (savedBypass == null);

            if (savedBypass != null) {
                mBypassPackages.addAll(savedBypass);
            }

            List<AppInfo> loaded = new ArrayList<>();
            int detectedRu = 0;

            for (ApplicationInfo ai : installed) {
                if (ai.packageName.equals(getPackageName())) continue;

                boolean isSystem = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                boolean isUpdatedSystem = (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
                boolean hasLaunch = pm.getLaunchIntentForPackage(ai.packageName) != null;
                boolean isRu = isRussianApp(ai.packageName, null);

                // Filter out system internals: skip core android/hardware/vendor system services
                if (isSystem && !isUpdatedSystem && !isRu && !mBypassPackages.contains(ai.packageName)) {
                    // Only show system app if it is an actual launchable user-facing app (like Chrome, YouTube)
                    // and not an internal android framework/vendor service
                    if (!hasLaunch) {
                        continue;
                    }
                    String pkg = ai.packageName.toLowerCase();
                    if (pkg.startsWith("android") ||
                        pkg.startsWith("com.android.") ||
                        pkg.startsWith("com.google.android.overlay") ||
                        pkg.startsWith("com.google.android.ext.") ||
                        pkg.startsWith("com.qualcomm.") ||
                        pkg.startsWith("vendor.") ||
                        pkg.startsWith("com.sec.android.app.billing") ||
                        pkg.equals("com.android.systemui") ||
                        pkg.contains("telephony") ||
                        pkg.contains("bluetooth") ||
                        pkg.contains("pacprocessor")) {
                        continue;
                    }
                }

                // Show user apps, launchable user-facing apps, Russian apps, or already configured apps
                if (!isSystem || isUpdatedSystem || hasLaunch || isRu || mBypassPackages.contains(ai.packageName)) {
                    AppInfo info = new AppInfo();
                    info.packageName = ai.packageName;
                    CharSequence labelSeq = pm.getApplicationLabel(ai);
                    info.label = (labelSeq != null && labelSeq.length() > 0) ? labelSeq.toString() : ai.packageName;

                    // Re-check heuristic with application label
                    info.isRussian = isRussianApp(ai.packageName, info.label);
                    if (info.isRussian) detectedRu++;

                    try {
                        info.icon = pm.getApplicationIcon(ai);
                    } catch (Exception e) {
                        try {
                            info.icon = getResources().getDrawable(R.drawable.ic_shield);
                        } catch (Exception ignored) {}
                    }

                    if (isFirstRun) {
                        // First run default: automatically route detected Russian services directly
                        info.isDirect = info.isRussian;
                        if (info.isDirect) {
                            mBypassPackages.add(info.packageName);
                        }
                    } else {
                        info.isDirect = mBypassPackages.contains(ai.packageName);
                    }

                    if (!info.isDirect) {
                        mVpnPackages.add(info.packageName);
                    }

                    loaded.add(info);
                }
            }

            // Save initial defaults if first run
            if (isFirstRun) {
                savePreferences();
            }

            Collections.sort(loaded);
            mDetectedRuCount = detectedRu;

            runOnUiThread(() -> {
                mAllApps.clear();
                mAllApps.addAll(loaded);

                if (mProgressBar != null) mProgressBar.setVisibility(View.GONE);
                if (mListView != null) mListView.setVisibility(View.VISIBLE);

                // Update Smart Analysis Banner
                if (mCardSmartAnalysis != null) {
                    if (mDetectedRuCount > 0) {
                        mCardSmartAnalysis.setVisibility(View.VISIBLE);
                        if (mTvSmartTitle != null) {
                            mTvSmartTitle.setText("🛡️ Умный анализ: найдено " + mDetectedRuCount + " сервисов РФ");
                        }
                        if (mTvSmartDesc != null) {
                            mTvSmartDesc.setText("Банки РФ, Госуслуги и доставка блокируют иностранные IP. AEGS рекомендует пустить их напрямую в обход VPN.");
                        }
                        if (mBtnApplySmartRu != null) {
                            mBtnApplySmartRu.setText("⚡ Настроить все " + mDetectedRuCount + " сервисов РФ в обход VPN");
                        }
                    } else {
                        mCardSmartAnalysis.setVisibility(View.GONE);
                    }
                }

                applyQueryAndFilter();
            });
        }).start();
    }

    private void applyQueryAndFilter() {
        String query = mEtSearch != null ? mEtSearch.getText().toString().trim().toLowerCase() : "";
        mDisplayedApps.clear();

        int totalDirect = 0;
        int totalVpn = 0;

        for (AppInfo app : mAllApps) {
            if (app.isDirect) {
                totalDirect++;
            } else {
                totalVpn++;
            }

            boolean matchesQuery = query.isEmpty() ||
                    app.label.toLowerCase().contains(query) ||
                    app.packageName.toLowerCase().contains(query);

            if (!matchesQuery) continue;

            if (mCurrentFilter == 1 && app.isDirect) continue;       // VPN only filter
            if (mCurrentFilter == 2 && !app.isDirect) continue;      // Direct only filter
            if (mCurrentFilter == 3 && !app.isRussian) continue;     // Russian only filter

            mDisplayedApps.add(app);
        }

        mAdapter.notifyDataSetChanged();

        if (mTvSubtitle != null) {
            String modePrefix = (mRoutingMode == 1) ? "[VPN Only] " : "[Bypass] ";
            mTvSubtitle.setText(modePrefix + totalVpn + " через VPN • " + totalDirect + " напрямую • " + mDetectedRuCount + " РФ");
        }
    }

    private void savePreferences() {
        mPrefs.edit()
                .putStringSet("custom_bypass_packages", new HashSet<>(mBypassPackages))
                .putStringSet("custom_vpn_packages", new HashSet<>(mVpnPackages))
                .putInt("routing_mode", mRoutingMode)
                .apply();
    }

    public static boolean isRussianApp(String pkg, String label) {
        if (pkg == null) return false;
        String pkgLower = pkg.toLowerCase();

        if (RU_KNOWN_PACKAGES.contains(pkgLower)) return true;
        if (pkgLower.startsWith("ru.") || pkgLower.startsWith("su.")) return true;

        if (pkgLower.contains(".yandex.") || pkgLower.contains(".sber") ||
                pkgLower.contains(".tinkoff") || pkgLower.contains(".tbank") ||
                pkgLower.contains(".vtb") || pkgLower.contains(".gosuslugi") ||
                pkgLower.contains(".alfabank") || pkgLower.contains(".ozon") ||
                pkgLower.contains(".wildberries") || pkgLower.contains(".vk.") ||
                pkgLower.contains(".mail.") || pkgLower.contains(".avito") ||
                pkgLower.contains(".rutube") || pkgLower.contains(".kinopoisk") ||
                pkgLower.contains(".mirpay")) {
            return true;
        }

        if (label != null) {
            String lblLower = label.toLowerCase();
            if (lblLower.contains("сбер") || lblLower.contains("тинькофф") || lblLower.contains("т-банк") ||
                    lblLower.contains("втб") || lblLower.contains("альфа") || lblLower.contains("госуслуги") ||
                    lblLower.contains("озон") || lblLower.contains("ozon") || lblLower.contains("вайлдберриз") ||
                    lblLower.contains("wildberries") || lblLower.contains("авито") || lblLower.contains("avito") ||
                    lblLower.contains("яндекс") || lblLower.contains("yandex") || lblLower.contains("самокат") ||
                    lblLower.contains("мир pay") || lblLower.contains("вконтакте") || lblLower.contains("рутуб") ||
                    lblLower.contains("rutube") || lblLower.contains("почта россии") || lblLower.contains("мой налог") ||
                    lblLower.contains("купер") || lblLower.contains("деливери") || lblLower.contains("кинопоиск")) {
                return true;
            }
        }
        return false;
    }

    class AppAdapter extends BaseAdapter {
        @Override
        public int getCount() {
            return mDisplayedApps.size();
        }

        @Override
        public Object getItem(int position) {
            return mDisplayedApps.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            ViewHolder holder;
            if (convertView == null) {
                convertView = LayoutInflater.from(AppRoutingActivity.this)
                        .inflate(R.layout.item_app_routing, parent, false);
                holder = new ViewHolder();
                holder.ivIcon = convertView.findViewById(R.id.iv_app_icon);
                holder.tvName = convertView.findViewById(R.id.tv_app_name);
                holder.tvBadge = convertView.findViewById(R.id.tv_app_badge);
                holder.tvPkg = convertView.findViewById(R.id.tv_app_pkg);
                holder.tvStatus = convertView.findViewById(R.id.tv_routing_status);
                holder.swRouting = convertView.findViewById(R.id.sw_app_routing);
                convertView.setTag(holder);
            } else {
                holder = (ViewHolder) convertView.getTag();
            }

            final AppInfo app = mDisplayedApps.get(position);
            holder.tvName.setText(app.label);
            holder.tvPkg.setText(app.packageName);

            if (app.icon != null) {
                holder.ivIcon.setImageDrawable(app.icon);
            }

            // Russian badge
            if (holder.tvBadge != null) {
                if (app.isRussian) {
                    holder.tvBadge.setVisibility(View.VISIBLE);
                    holder.tvBadge.setText("🇷🇺 РФ");
                } else {
                    holder.tvBadge.setVisibility(View.GONE);
                }
            }

            // Status label & switch
            // Switch: checked = through VPN tunnel, unchecked = direct bypass
            holder.swRouting.setOnCheckedChangeListener(null);
            holder.swRouting.setChecked(!app.isDirect);

            updateItemStatusText(holder.tvStatus, app.isDirect);

            holder.swRouting.setOnCheckedChangeListener((buttonView, isChecked) -> {
                app.isDirect = !isChecked;
                if (app.isDirect) {
                    mBypassPackages.add(app.packageName);
                    mVpnPackages.remove(app.packageName);
                } else {
                    mBypassPackages.remove(app.packageName);
                    mVpnPackages.add(app.packageName);
                }
                updateItemStatusText(holder.tvStatus, app.isDirect);
                savePreferences();

                if (mTvSubtitle != null) {
                    int directCount = 0;
                    for (AppInfo a : mAllApps) {
                        if (a.isDirect) directCount++;
                    }
                    String modePrefix = (mRoutingMode == 1) ? "[VPN Only] " : "[Bypass] ";
                    mTvSubtitle.setText(modePrefix + (mAllApps.size() - directCount) + " через VPN • " + directCount + " напрямую • " + mDetectedRuCount + " РФ");
                }
            });

            return convertView;
        }

        private void updateItemStatusText(TextView tvStatus, boolean isDirect) {
            if (tvStatus == null) return;
            if (mRoutingMode == 1) {
                // VPN only mode
                if (!isDirect) {
                    tvStatus.setText("⚡ В туннеле VPN");
                    tvStatus.setTextColor(Color.parseColor("#F59E0B"));
                } else {
                    tvStatus.setText("➡️ Вне VPN (напрямую)");
                    tvStatus.setTextColor(Color.parseColor("#A8A29E"));
                }
            } else {
                // Bypass mode
                if (!isDirect) {
                    tvStatus.setText("⚡ Через VPN");
                    tvStatus.setTextColor(Color.parseColor("#F59E0B"));
                } else {
                    tvStatus.setText("➡️ Напрямую (обход VPN)");
                    tvStatus.setTextColor(Color.parseColor("#34D399"));
                }
            }
        }

        class ViewHolder {
            ImageView ivIcon;
            TextView tvName;
            TextView tvBadge;
            TextView tvPkg;
            TextView tvStatus;
            SwitchCompat swRouting;
        }
    }
}
