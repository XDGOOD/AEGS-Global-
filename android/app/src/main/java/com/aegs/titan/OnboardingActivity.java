package com.aegs.titan;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class OnboardingActivity extends AppCompatActivity {

    private AnimShieldSpeedometerView mAnimView;
    private LinearLayout mLlSourceSelector;
    private View mCardGetBotKey;
    private View mCardPasteKey;
    private TextView mTvCardPasteTitle;
    private TextView mTvCardPasteSub;

    private TextView mTvTitle;
    private TextView mTvSubtitle;
    private Button mBtnNext;
    private View mDot0, mDot1, mDot2, mDot3;

    private int mCurrentStep = 0;
    private boolean mKeyConfigured = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_onboarding);

        mAnimView = findViewById(R.id.anim_view);
        mLlSourceSelector = findViewById(R.id.ll_source_selector);
        mCardGetBotKey = findViewById(R.id.card_source_cloud);
        mCardPasteKey = findViewById(R.id.card_source_vps);
        mTvCardPasteTitle = findViewById(R.id.tv_card_paste_title);
        mTvCardPasteSub = findViewById(R.id.tv_card_paste_sub);

        mTvTitle = findViewById(R.id.tv_title);
        mTvSubtitle = findViewById(R.id.tv_subtitle);
        mBtnNext = findViewById(R.id.btn_next);

        mDot0 = findViewById(R.id.dot_0);
        mDot1 = findViewById(R.id.dot_1);
        mDot2 = findViewById(R.id.dot_2);
        mDot3 = findViewById(R.id.dot_3);

        if (mCardGetBotKey != null) {
            mCardGetBotKey.setOnClickListener(v -> {
                try {
                    Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/aegs_support_bot"));
                    startActivity(intent);
                } catch (Exception e) {
                    Toast.makeText(this, "Откройте Telegram: @aegs_support_bot", Toast.LENGTH_LONG).show();
                }
            });
        }

        if (mCardPasteKey != null) {
            mCardPasteKey.setOnClickListener(v -> handlePasteKey());
        }

        mBtnNext.setOnClickListener(v -> advanceStep());

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (mCurrentStep > 0) {
                    mCurrentStep--;
                    updateStepDisplay();
                } else {
                    finishOnboarding();
                }
            }
        });

        updateStepDisplay();
    }

    private void handlePasteKey() {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null && cm.hasPrimaryClip() && cm.getPrimaryClip().getItemCount() > 0) {
                CharSequence cs = cm.getPrimaryClip().getItemAt(0).getText();
                if (cs != null) {
                    String clipStr = cs.toString().trim();
                    boolean saved = parseAndSaveKey(clipStr);
                    if (saved) {
                        mKeyConfigured = true;
                        if (mTvCardPasteTitle != null) {
                            mTvCardPasteTitle.setText("✓ Ключ успешно сохранен!");
                            mTvCardPasteTitle.setTextColor(0xFF34D399);
                        }
                        if (mTvCardPasteSub != null) {
                            mTvCardPasteSub.setText("Ключ активирован в приложении. Нажмите «Запустить AEGS».");
                        }
                        mBtnNext.setText("🚀 Запустить AEGS");
                        Toast.makeText(this, "Ключ AEGS успешно активирован!", Toast.LENGTH_SHORT).show();
                        return;
                    }
                }
            }
            Toast.makeText(this, "Скопируйте ключ aegs:// или токен в боте @aegs_support_bot перед вставкой", Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, "Не удалось прочитать буфер обмена", Toast.LENGTH_SHORT).show();
        }
    }

    private boolean parseAndSaveKey(String text) {
        if (text == null || text.isEmpty()) return false;

        String ip = "31.76.9.86";
        int port = 50001;
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
                    if (path != null && path.startsWith("/")) path = path.substring(1);
                    if (path != null && !path.isEmpty()) token = path;
                }
            } catch (Exception ignored) {}
        } else if (text.length() >= 16) {
            token = text;
        }

        if (token == null || token.length() < 16) {
            return false;
        }

        String keyId = computeKeyId(token);
        SharedPreferences prefs = getSharedPreferences(SettingsActivity.PREFS_NAME, MODE_PRIVATE);
        prefs.edit()
                .putString(MainActivity.KEY_TOKEN, token)
                .putString(MainActivity.KEY_SERVER_IP, ip)
                .putInt(MainActivity.KEY_SERVER_PORT, port)
                .putString(MainActivity.KEY_KEY_ID, keyId)
                .putBoolean(MainActivity.KEY_HAS_ACTIVE_KEY, true)
                .apply();

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

    private void advanceStep() {
        if (mCurrentStep < 3) {
            mCurrentStep++;
            updateStepDisplay();
        } else {
            finishOnboarding();
        }
    }

    private void updateStepDisplay() {
        if (mCurrentStep == 0) {
            mAnimView.setVisibility(View.VISIBLE);
            mLlSourceSelector.setVisibility(View.GONE);
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_WELCOME);

            mTvTitle.setText("Добро пожаловать в AEGS");
            mTvSubtitle.setText("Новейший протокол v6 Titan для надежного обхода DPI и блокировок любого уровня.");
            mBtnNext.setText("Далее");

            setDotState(mDot0, true);
            setDotState(mDot1, false);
            setDotState(mDot2, false);
            setDotState(mDot3, false);

        } else if (mCurrentStep == 1) {
            mAnimView.setVisibility(View.VISIBLE);
            mLlSourceSelector.setVisibility(View.GONE);
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_LOCK);

            mTvTitle.setText("Абсолютная защита");
            mTvSubtitle.setText("Шифрование ChaCha20-Poly1305 и маскировка заголовков под Chrome 128+ Reality ECH.");
            mBtnNext.setText("Далее");

            setDotState(mDot0, false);
            setDotState(mDot1, true);
            setDotState(mDot2, false);
            setDotState(mDot3, false);

        } else if (mCurrentStep == 2) {
            mAnimView.setVisibility(View.VISIBLE);
            mLlSourceSelector.setVisibility(View.GONE);
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_SPEEDOMETER);

            mTvTitle.setText("Скорость до 940+ Мбит/с");
            mTvSubtitle.setText("Оптимизация zero-copy ядра. Мгновенный отклик, 4K видео и минимальный пинг.");
            mBtnNext.setText("Далее");

            setDotState(mDot0, false);
            setDotState(mDot1, false);
            setDotState(mDot2, true);
            setDotState(mDot3, false);

        } else if (mCurrentStep == 3) {
            mAnimView.setVisibility(View.GONE);
            mLlSourceSelector.setVisibility(View.VISIBLE);

            mTvTitle.setText("🔑 Ключ доступа к сети");
            mTvSubtitle.setText("Для работы протокола необходим персональный ключ доступа (100 руб/мес, до 4 устройств). Оформите подписку в боте @aegs_support_bot.");

            if (mKeyConfigured) {
                mBtnNext.setText("🚀 Запустить AEGS");
            } else {
                mBtnNext.setText("Перейти в приложение");
            }

            setDotState(mDot0, false);
            setDotState(mDot1, false);
            setDotState(mDot2, false);
            setDotState(mDot3, true);
        }
    }

    private void setDotState(View dot, boolean active) {
        if (dot == null) return;
        dot.setBackgroundColor(active ? 0xFFF59E0B : 0xFF2E2820);
        dot.getLayoutParams().width = (int) ((active ? 24 : 8) * getResources().getDisplayMetrics().density);
        dot.requestLayout();
    }

    private void finishOnboarding() {
        SharedPreferences prefs = getSharedPreferences(SettingsActivity.PREFS_NAME, MODE_PRIVATE);
        prefs.edit()
                .putBoolean("onboarding_complete", true)
                .putBoolean("onboarding_done", true)
                .apply();

        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
        finish();
    }
}
