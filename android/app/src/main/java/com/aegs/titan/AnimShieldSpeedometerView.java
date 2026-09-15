package com.aegs.titan;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.OvershootInterpolator;

import androidx.annotation.Nullable;

public class AnimShieldSpeedometerView extends View {

    public static final int MODE_WELCOME = 0;
    public static final int MODE_LOCK = 1;
    public static final int MODE_SPEEDOMETER = 2;

    private int mCurrentMode = MODE_WELCOME;

    // Paints
    private Paint mPaintBody;
    private Paint mPaintShackle;
    private Paint mPaintGlow;
    private Paint mPaintGauge;
    private Paint mPaintNeedle;
    private Paint mPaintText;
    private Paint mPaintSubText;

    // Animators & Values
    private float mPulseProgress = 0f;
    private float mShackleOffset = 0f;    // 0 = open, 1 = locked
    private float mLockGlowAlpha = 0f;     // Glow on snap
    private float mNeedleAngle = 0f;       // 0 to 1 ratio on arc
    private float mSpeedDisplayVal = 0f;   // 0 to 940 Mbps

    private ValueAnimator mPulseAnim;
    private ValueAnimator mLockAnim;
    private ValueAnimator mSpeedAnim;

    public AnimShieldSpeedometerView(Context context) {
        super(context);
        init();
    }

    public AnimShieldSpeedometerView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public AnimShieldSpeedometerView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        mPaintBody = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintBody.setColor(0xFF2563EB); // AEGS Blue
        mPaintBody.setStyle(Paint.Style.FILL);

        mPaintShackle = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintShackle.setColor(0xFFE2E8F0);
        mPaintShackle.setStyle(Paint.Style.STROKE);
        mPaintShackle.setStrokeWidth(14f);
        mPaintShackle.setStrokeCap(Paint.Cap.ROUND);

        mPaintGlow = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintGlow.setColor(0xFF10B981); // Emerald green
        mPaintGlow.setStyle(Paint.Style.STROKE);
        mPaintGlow.setStrokeWidth(8f);

        mPaintGauge = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintGauge.setStyle(Paint.Style.STROKE);
        mPaintGauge.setStrokeCap(Paint.Cap.ROUND);

        mPaintNeedle = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintNeedle.setColor(0xFF10B981);
        mPaintNeedle.setStyle(Paint.Style.STROKE);
        mPaintNeedle.setStrokeWidth(8f);
        mPaintNeedle.setStrokeCap(Paint.Cap.ROUND);

        mPaintText = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintText.setColor(0xFFFFFFFF);
        mPaintText.setTextAlign(Paint.Align.CENTER);
        mPaintText.setFakeBoldText(true);

        mPaintSubText = new Paint(Paint.ANTI_ALIAS_FLAG);
        mPaintSubText.setColor(0xFF94A3B8);
        mPaintSubText.setTextAlign(Paint.Align.CENTER);

        startPulseAnimation();
    }

    public void setMode(int mode) {
        mCurrentMode = mode;
        if (mode == MODE_WELCOME) {
            startPulseAnimation();
        } else if (mode == MODE_LOCK) {
            if (mPulseAnim != null) mPulseAnim.cancel();
            startLockAnimation();
        } else if (mode == MODE_SPEEDOMETER) {
            if (mPulseAnim != null) mPulseAnim.cancel();
            if (mLockAnim != null) mLockAnim.cancel();
            startSpeedometerAnimation();
        }
        invalidate();
    }

    private void startPulseAnimation() {
        if (mPulseAnim != null) mPulseAnim.cancel();
        mPulseAnim = ValueAnimator.ofFloat(0f, 1f);
        mPulseAnim.setDuration(1800);
        mPulseAnim.setRepeatCount(ValueAnimator.INFINITE);
        mPulseAnim.setRepeatMode(ValueAnimator.REVERSE);
        mPulseAnim.setInterpolator(new AccelerateDecelerateInterpolator());
        mPulseAnim.addUpdateListener(animation -> {
            mPulseProgress = (float) animation.getAnimatedValue();
            invalidate();
        });
        mPulseAnim.start();
    }

    public void startLockAnimation() {
        if (mLockAnim != null) mLockAnim.cancel();
        mShackleOffset = 0f;
        mLockGlowAlpha = 0f;

        mLockAnim = ValueAnimator.ofFloat(0f, 1f);
        mLockAnim.setDuration(900);
        mLockAnim.setInterpolator(new OvershootInterpolator(1.2f));
        mLockAnim.addUpdateListener(animation -> {
            mShackleOffset = (float) animation.getAnimatedValue();
            if (mShackleOffset > 0.8f) {
                mLockGlowAlpha = (mShackleOffset - 0.8f) * 5f; // Glow to 1.0
            }
            invalidate();
        });
        mLockAnim.start();
    }

    public void startSpeedometerAnimation() {
        if (mSpeedAnim != null) mSpeedAnim.cancel();
        mNeedleAngle = 0f;
        mSpeedDisplayVal = 0f;

        mSpeedAnim = ValueAnimator.ofFloat(0f, 1f);
        mSpeedAnim.setDuration(1200);
        mSpeedAnim.setInterpolator(new AccelerateDecelerateInterpolator());
        mSpeedAnim.addUpdateListener(animation -> {
            float val = (float) animation.getAnimatedValue();
            mNeedleAngle = val * 0.88f; // ~900 Mbps on gauge
            mSpeedDisplayVal = val * 940f;
            invalidate();
        });
        mSpeedAnim.start();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        float cx = getWidth() / 2f;
        float cy = getHeight() / 2f;
        float radius = Math.min(cx, cy) * 0.82f;

        if (mCurrentMode == MODE_WELCOME) {
            drawWelcomeMode(canvas, cx, cy, radius);
        } else if (mCurrentMode == MODE_LOCK) {
            drawLockMode(canvas, cx, cy, radius);
        } else if (mCurrentMode == MODE_SPEEDOMETER) {
            drawSpeedometerMode(canvas, cx, cy, radius);
        }
    }

    private void drawWelcomeMode(Canvas canvas, float cx, float cy, float radius) {
        // Glowing pulses
        mPaintGlow.setColor(0xFF2563EB);
        mPaintGlow.setStrokeWidth(4f + mPulseProgress * 8f);
        mPaintGlow.setAlpha((int) ((1f - mPulseProgress) * 160));
        canvas.drawCircle(cx, cy, radius * (0.85f + mPulseProgress * 0.22f), mPaintGlow);

        // Core Shield
        drawShield(canvas, cx, cy, radius * 0.7f, 0xFF2563EB);

        // Inner glowing symbol 'A'
        mPaintText.setTextSize(radius * 0.5f);
        mPaintText.setColor(0xFFFFFFFF);
        canvas.drawText("A", cx, cy + (radius * 0.18f), mPaintText);
    }

    private void drawLockMode(Canvas canvas, float cx, float cy, float radius) {
        float bodyW = radius * 0.9f;
        float bodyH = radius * 0.75f;
        float shackleR = radius * 0.42f;

        // Shackle movement (open -> snaps down)
        float shackleY = cy - bodyH * 0.2f - (1f - mShackleOffset) * (radius * 0.25f);

        // Shackle arc
        RectF shackleRect = new RectF(cx - shackleR, shackleY - shackleR * 1.5f, cx + shackleR, shackleY + shackleR * 0.5f);
        mPaintShackle.setColor(0xFFE2E8F0);
        canvas.drawArc(shackleRect, 180, 180, false, mPaintShackle);

        // Glow when locked
        if (mLockGlowAlpha > 0f) {
            mPaintGlow.setColor(0xFF10B981);
            mPaintGlow.setStrokeWidth(12f);
            mPaintGlow.setAlpha((int) (mLockGlowAlpha * 200));
            RectF glowRect = new RectF(cx - bodyW / 2f - 8f, cy - 8f, cx + bodyW / 2f + 8f, cy + bodyH + 8f);
            canvas.drawRoundRect(glowRect, 24f, 24f, mPaintGlow);
        }

        // Lock Body
        mPaintBody.setColor(0xFF1E293B);
        RectF bodyRect = new RectF(cx - bodyW / 2f, cy, cx + bodyW / 2f, cy + bodyH);
        canvas.drawRoundRect(bodyRect, 20f, 20f, mPaintBody);

        // Keyhole
        Paint keyPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        keyPaint.setColor(mShackleOffset > 0.8f ? 0xFF10B981 : 0xFF64748B);
        canvas.drawCircle(cx, cy + bodyH * 0.42f, radius * 0.12f, keyPaint);

        Path keyPath = new Path();
        keyPath.moveTo(cx - radius * 0.06f, cy + bodyH * 0.42f);
        keyPath.lineTo(cx + radius * 0.06f, cy + bodyH * 0.42f);
        keyPath.lineTo(cx + radius * 0.08f, cy + bodyH * 0.72f);
        keyPath.lineTo(cx - radius * 0.08f, cy + bodyH * 0.72f);
        keyPath.close();
        canvas.drawPath(keyPath, keyPaint);
    }

    private void drawSpeedometerMode(Canvas canvas, float cx, float cy, float radius) {
        float arcRadius = radius * 0.85f;
        RectF arcRect = new RectF(cx - arcRadius, cy - arcRadius, cx + arcRadius, cy + arcRadius);

        // Background Track
        mPaintGauge.setColor(0xFF1E293B);
        mPaintGauge.setStrokeWidth(16f);
        canvas.drawArc(arcRect, 135, 270, false, mPaintGauge);

        // Active Speed Gradient Arc
        mPaintGauge.setColor(0xFF10B981);
        mPaintGauge.setStrokeWidth(16f);
        canvas.drawArc(arcRect, 135, mNeedleAngle * 270f, false, mPaintGauge);

        // Center Speed text
        mPaintText.setTextSize(radius * 0.45f);
        mPaintText.setColor(0xFFFFFFFF);
        canvas.drawText(String.valueOf((int) mSpeedDisplayVal), cx, cy + radius * 0.05f, mPaintText);

        mPaintSubText.setTextSize(radius * 0.16f);
        mPaintSubText.setColor(0xFF10B981);
        canvas.drawText("МБИТ / СЕК", cx, cy + radius * 0.28f, mPaintSubText);

        // Center hub
        mPaintBody.setColor(0xFF10B981);
        canvas.drawCircle(cx, cy + radius * 0.48f, 10f, mPaintBody);
    }

    private void drawShield(Canvas canvas, float cx, float cy, float r, int color) {
        Path path = new Path();
        path.moveTo(cx, cy - r);
        path.lineTo(cx + r * 0.85f, cy - r * 0.55f);
        path.lineTo(cx + r * 0.85f, cy + r * 0.1f);
        path.quadTo(cx + r * 0.85f, cy + r * 0.75f, cx, cy + r);
        path.quadTo(cx - r * 0.85f, cy + r * 0.75f, cx - r * 0.85f, cy + r * 0.1f);
        path.lineTo(cx - r * 0.85f, cy - r * 0.55f);
        path.close();

        mPaintBody.setColor(color);
        canvas.drawPath(path, mPaintBody);
    }
}
