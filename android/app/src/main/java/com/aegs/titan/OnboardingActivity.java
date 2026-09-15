package com.aegs.titan;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

public class OnboardingActivity extends AppCompatActivity {

    private AnimShieldSpeedometerView mAnimView;
    private TextView mTvTitle;
    private TextView mTvSubtitle;
    private Button mBtnNext;
    private TextView mBtnSkip;
    private View mDot0, mDot1, mDot2;

    private int mCurrentStep = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_onboarding);

        mAnimView = findViewById(R.id.anim_view);
        mTvTitle = findViewById(R.id.tv_title);
        mTvSubtitle = findViewById(R.id.tv_subtitle);
        mBtnNext = findViewById(R.id.btn_next);
        mBtnSkip = findViewById(R.id.btn_skip);
        mDot0 = findViewById(R.id.dot_0);
        mDot1 = findViewById(R.id.dot_1);
        mDot2 = findViewById(R.id.dot_2);

        mBtnNext.setOnClickListener(v -> advanceStep());
        mBtnSkip.setOnClickListener(v -> finishOnboarding());

        updateStepDisplay(false);
    }

    private void advanceStep() {
        if (mCurrentStep < 2) {
            mCurrentStep++;
            updateStepDisplay(true);
        } else {
            finishOnboarding();
        }
    }

    private void updateStepDisplay(boolean animate) {
        if (mCurrentStep == 0) {
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_WELCOME);
            mTvTitle.setText("Добро пожаловать в AEGS VPN");
            mTvSubtitle.setText("Свободный, безопасный интернет без цензуры, слежки и искусственных ограничений провайдеров.");
            mBtnNext.setText("ДАЛЕЕ  →");
            mBtnNext.setBackgroundColor(0xFF2563EB);

            setDotActive(mDot0);
            setDotInactive(mDot1);
            setDotInactive(mDot2);

        } else if (mCurrentStep == 1) {
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_LOCK);
            if (animate) mAnimView.startLockAnimation();

            mTvTitle.setText("Абсолютная безопасность");
            mTvSubtitle.setText("Шифрование ChaCha20-Poly1305 и маскировка RFC 9000 QUIC. Замок защелкнут: для ТСПУ и операторов ваш трафик неотличим от обычного защищенного сайта.");
            mBtnNext.setText("ДАЛЕЕ  →");
            mBtnNext.setBackgroundColor(0xFF2563EB);

            setDotInactive(mDot0);
            setDotActive(mDot1);
            setDotInactive(mDot2);

        } else if (mCurrentStep == 2) {
            mAnimView.setMode(AnimShieldSpeedometerView.MODE_SPEEDOMETER);
            if (animate) mAnimView.startSpeedometerAnimation();

            mTvTitle.setText("Скорость до 900+ Мбит/с");
            mTvSubtitle.setText("Zero-copy архитектура и оптимизация буферов. Мгновенная загрузка 4K-видео на YouTube, минимальный пинг и стабильность в играх.");
            mBtnNext.setText("НАЧАТЬ РАБОТУ  🚀");
            mBtnNext.setBackgroundColor(0xFF10B981);

            setDotInactive(mDot0);
            setDotInactive(mDot1);
            setDotActive(mDot2);
        }
    }

    private void setDotActive(View dot) {
        dot.setBackgroundColor(0xFF2563EB);
        dot.getLayoutParams().width = (int)(24 * getResources().getDisplayMetrics().density);
        dot.requestLayout();
    }

    private void setDotInactive(View dot) {
        dot.setBackgroundColor(0xFF1E293B);
        dot.getLayoutParams().width = (int)(8 * getResources().getDisplayMetrics().density);
        dot.requestLayout();
    }

    private void finishOnboarding() {
        SharedPreferences prefs = getSharedPreferences("aegs_prefs", MODE_PRIVATE);
        prefs.edit().putBoolean("onboarding_done", true).apply();

        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
        finish();
    }
}
