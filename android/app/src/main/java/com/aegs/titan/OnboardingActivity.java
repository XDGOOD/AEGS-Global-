package com.aegs.titan;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

public class OnboardingActivity extends AppCompatActivity {

    private AnimShieldSpeedometerView mAnimView;
    private LinearLayout mLlSourceSelector;
    private View mCardCloud;
    private View mCardVps;

    private TextView mTvTitle;
    private TextView mTvSubtitle;
    private Button mBtnNext;
    private TextView mBtnSkip;
    private View mDot0, mDot1, mDot2, mDot3;

    private int mCurrentStep = 0;
    private boolean mSelectedVps = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_onboarding);

        mAnimView = findViewById(R.id.anim_view);
        mLlSourceSelector = findViewById(R.id.ll_source_selector);
        mCardCloud = findViewById(R.id.card_source_cloud);
        mCardVps = findViewById(R.id.card_source_vps);

        mTvTitle = findViewById(R.id.tv_title);
        mTvSubtitle = findViewById(R.id.tv_subtitle);
        mBtnNext = findViewById(R.id.btn_next);
        mBtnSkip = findViewById(R.id.btn_skip);

        mDot0 = findViewById(R.id.dot_0);
        mDot1 = findViewById(R.id.dot_1);
        mDot2 = findViewById(R.id.dot_2);
        mDot3 = findViewById(R.id.dot_3);

        if (mCardCloud != null) {
            mCardCloud.setOnClickListener(v -> {
                mSelectedVps = false;
                mCardCloud.setBackgroundResource(R.drawable.card_obsidian);
                mCardVps.setBackgroundResource(R.drawable.card_obsidian);
                mCardCloud.setAlpha(1.0f);
                mCardVps.setAlpha(0.6f);
            });
        }
        if (mCardVps != null) {
            mCardVps.setOnClickListener(v -> {
                mSelectedVps = true;
                mCardVps.setBackgroundResource(R.drawable.card_obsidian);
                mCardCloud.setBackgroundResource(R.drawable.card_obsidian);
                mCardVps.setAlpha(1.0f);
                mCardCloud.setAlpha(0.6f);
            });
        }

        mBtnNext.setOnClickListener(v -> advanceStep());
        mBtnSkip.setOnClickListener(v -> finishOnboarding());

        // Handle Back button: step back if on step 1-3, else finish
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
            mTvSubtitle.setText("Свободный и безопасный интернет без цензуры, слежки и замедлений провайдера.");
            mBtnNext.setText("ДАЛЕЕ");

            setDotState(mDot0, true);
            setDotState(mDot1, false);
            setDotState(mDot2, false);
            setDotState(mDot3, false);

        } else if (mCurrentStep == 1) {
            mAnimView.setVisibility(View.VISIBLE);
            mLlSourceSelector.setVisibility(View.GONE);
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_LOCK);

            mTvTitle.setText("Абсолютная безопасность");
            mTvSubtitle.setText("Шифрование ChaCha20-Poly1305 и маскировка Chrome 128+ Reality ECH. Трафик неотличим от HTTPS.");
            mBtnNext.setText("ДАЛЕЕ");

            setDotState(mDot0, false);
            setDotState(mDot1, true);
            setDotState(mDot2, false);
            setDotState(mDot3, false);

        } else if (mCurrentStep == 2) {
            mAnimView.setVisibility(View.VISIBLE);
            mLlSourceSelector.setVisibility(View.GONE);
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_SPEEDOMETER);

            mTvTitle.setText("Скорость до 940+ Мбит/с");
            mTvSubtitle.setText("Аппаратное zero-copy ядро. Мгновенная загрузка 4K видео на YouTube и минимальный пинг в играх.");
            mBtnNext.setText("ДАЛЕЕ");

            setDotState(mDot0, false);
            setDotState(mDot1, false);
            setDotState(mDot2, true);
            setDotState(mDot3, false);

        } else if (mCurrentStep == 3) {
            mAnimView.setVisibility(View.GONE);
            mLlSourceSelector.setVisibility(View.VISIBLE);

            mTvTitle.setText("Выберите способ подключения");
            mTvSubtitle.setText("Используйте встроенный защищенный кластер AEGS или настройте подключение к своему VPS.");
            mBtnNext.setText("ЗАПУСТИТЬ AEGS  🚀");

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
                .putBoolean("mode_vps", mSelectedVps)
                .apply();

        if (isTaskRoot()) {
            Intent intent = new Intent(this, MainActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
        }
        finish();
    }
}
