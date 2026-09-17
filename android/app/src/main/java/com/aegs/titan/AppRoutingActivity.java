package com.aegs.titan;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
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
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AppRoutingActivity extends AppCompatActivity {
    private SharedPreferences mPrefs;
    private final Set<String> mBypassPackages = new HashSet<>();

    private final List<AppInfo> mAllApps = new ArrayList<>();
    private final List<AppInfo> mDisplayedApps = new ArrayList<>();

    private AppAdapter mAdapter;
    private ProgressBar mProgressBar;
    private ListView mListView;
    private TextView mTvSubtitle;
    private EditText mEtSearch;

    private TextView mBtnFilterAll;
    private TextView mBtnFilterVpn;
    private TextView mBtnFilterDirect;
    private int mCurrentFilter = 0; // 0: All, 1: VPN only, 2: Direct only

    private static final String[] DEFAULT_BYPASS = {
            "ru.sberbankmobile", "com.idamob.tinkoff.android", "ru.vtb24.mobilebanking",
            "ru.alfabank.mobile.android", "ru.gosuslugi.net", "ru.yandex.searchplugin",
            "com.vkontakte.android", "ru.ozon.app.android", "com.wildberries.ru"
    };

    static class AppInfo implements Comparable<AppInfo> {
        String label;
        String packageName;
        Drawable icon;
        boolean isDirect; // true = bypass VPN, false = tunnel via VPN

        @Override
        public int compareTo(AppInfo o) {
            return this.label.compareToIgnoreCase(o.label);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_routing);

        mPrefs = getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE);
        Set<String> savedBypass = mPrefs.getStringSet("custom_bypass_packages", null);
        if (savedBypass != null) {
            mBypassPackages.addAll(savedBypass);
        } else {
            mBypassPackages.addAll(Arrays.asList(DEFAULT_BYPASS));
        }

        View btnBack = findViewById(R.id.btn_back_routing);
        if (btnBack != null) {
            btnBack.setOnClickListener(v -> finish());
        }

        mTvSubtitle = findViewById(R.id.tv_routing_subtitle);
        mProgressBar = findViewById(R.id.pb_loading_apps);
        mListView = findViewById(R.id.lv_apps);
        mEtSearch = findViewById(R.id.et_search_apps);

        mBtnFilterAll = findViewById(R.id.btn_filter_all);
        mBtnFilterVpn = findViewById(R.id.btn_filter_vpn);
        mBtnFilterDirect = findViewById(R.id.btn_filter_direct);

        setupFilters();
        setupSearch();

        mAdapter = new AppAdapter();
        mListView.setAdapter(mAdapter);

        loadInstalledApps();
    }

    private void setupFilters() {
        if (mBtnFilterAll != null) {
            mBtnFilterAll.setOnClickListener(v -> setFilter(0));
        }
        if (mBtnFilterVpn != null) {
            mBtnFilterVpn.setOnClickListener(v -> setFilter(1));
        }
        if (mBtnFilterDirect != null) {
            mBtnFilterDirect.setOnClickListener(v -> setFilter(2));
        }
    }

    private void setFilter(int filterMode) {
        mCurrentFilter = filterMode;
        if (mBtnFilterAll != null) {
            mBtnFilterAll.setBackgroundResource(filterMode == 0 ? R.drawable.bg_btn_amber : R.drawable.bg_input_rounded);
            mBtnFilterAll.setTextColor(filterMode == 0 ? getResources().getColor(R.color.text_on_amber) : getResources().getColor(R.color.text_primary));
        }
        if (mBtnFilterVpn != null) {
            mBtnFilterVpn.setBackgroundResource(filterMode == 1 ? R.drawable.bg_btn_amber : R.drawable.bg_input_rounded);
            mBtnFilterVpn.setTextColor(filterMode == 1 ? getResources().getColor(R.color.text_on_amber) : getResources().getColor(R.color.text_primary));
        }
        if (mBtnFilterDirect != null) {
            mBtnFilterDirect.setBackgroundResource(filterMode == 2 ? R.drawable.bg_btn_amber : R.drawable.bg_input_rounded);
            mBtnFilterDirect.setTextColor(filterMode == 2 ? getResources().getColor(R.color.text_on_amber) : getResources().getColor(R.color.text_primary));
        }
        applyQueryAndFilter();
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
            List<AppInfo> loaded = new ArrayList<>();

            for (ApplicationInfo ai : installed) {
                boolean isSystem = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                boolean hasLaunch = pm.getLaunchIntentForPackage(ai.packageName) != null;
                boolean isSaved = mBypassPackages.contains(ai.packageName);

                if (!isSystem || hasLaunch || isSaved) {
                    AppInfo info = new AppInfo();
                    info.packageName = ai.packageName;
                    CharSequence labelSeq = pm.getApplicationLabel(ai);
                    info.label = (labelSeq != null && labelSeq.length() > 0) ? labelSeq.toString() : ai.packageName;
                    try {
                        info.icon = pm.getApplicationIcon(ai);
                    } catch (Exception e) {
                        info.icon = getResources().getDrawable(R.drawable.ic_shield);
                    }
                    info.isDirect = mBypassPackages.contains(ai.packageName);
                    loaded.add(info);
                }
            }

            Collections.sort(loaded);

            runOnUiThread(() -> {
                mAllApps.clear();
                mAllApps.addAll(loaded);
                mProgressBar.setVisibility(View.GONE);
                mListView.setVisibility(View.VISIBLE);
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

            if (mCurrentFilter == 1 && app.isDirect) continue; // VPN only filter
            if (mCurrentFilter == 2 && !app.isDirect) continue; // Direct only filter

            mDisplayedApps.add(app);
        }

        mAdapter.notifyDataSetChanged();
        if (mTvSubtitle != null) {
            mTvSubtitle.setText(totalVpn + " через VPN • " + totalDirect + " напрямую");
        }
    }

    private void saveBypassPreferences() {
        mPrefs.edit().putStringSet("custom_bypass_packages", new HashSet<>(mBypassPackages)).apply();
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
                holder.tvPkg = convertView.findViewById(R.id.tv_app_pkg);
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

            // Switch: checked = VPN tunnel, unchecked = direct bypass
            holder.swRouting.setOnCheckedChangeListener(null);
            holder.swRouting.setChecked(!app.isDirect);

            holder.swRouting.setOnCheckedChangeListener((buttonView, isChecked) -> {
                app.isDirect = !isChecked;
                if (app.isDirect) {
                    mBypassPackages.add(app.packageName);
                } else {
                    mBypassPackages.remove(app.packageName);
                }
                saveBypassPreferences();
                if (mTvSubtitle != null) {
                    int directCount = 0;
                    for (AppInfo a : mAllApps) {
                        if (a.isDirect) directCount++;
                    }
                    mTvSubtitle.setText((mAllApps.size() - directCount) + " через VPN • " + directCount + " напрямую");
                }
            });

            return convertView;
        }

        class ViewHolder {
            ImageView ivIcon;
            TextView tvName;
            TextView tvPkg;
            SwitchCompat swRouting;
        }
    }
}
