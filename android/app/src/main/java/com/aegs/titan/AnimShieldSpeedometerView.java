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
import android.view.animation.DecelerateInterpolator;

import androidx.annotation.Nullable;

public class AnimShieldSpeedometerView extends View {

    public static final int MODE_WELCOME = 0;
    public static final int MODE_LOCK = 1;
    public static final int MODE_SPEEDOMETER = 2;

    private int mCurrentMode = MODE_WELCOME;

    // Palette: Obsidian & Warm Amber
    private static final int COLOR_AMBER = 0xFFF59E0B;
    private static final int COLOR_AMBER_GLOW = 0x47F59E0B;
    private static final int COLOR_ORANGE = 0xFFFB923C;
    private static final int COLOR_OBSIDIAN_BODY = 0xFF1C1917;
    private static final int COLOR_SHACKLE = 0xFFD4D4D8;
    private static final int COLOR_TRACK = 0x14FFFFFF;
    private static final int COLOR_TICK_INACTIVE = 0xFF334155;

    // Paints
    private final Paint mPaintStroke = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint mPaintFill = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint mPaintText = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint mPaintSubText = new Paint(Paint.ANTI_ALIAS_FLAG);

    // Animators & Values
    private float mPulseProgress = 0f;
    private float mShackleProgress = 1f; // 0 = open, 1 = locked
    private float mLockGlow = 0f;        // Shockwave 0..1
    private float mSpeedProgress = 0f;   // 0..1
    private float mDisplayedSpeed = 0f;  // 0..940

    private ValueAnimator mPulseAnim;
    private ValueAnimator mLockAnim;
    private ValueAnimator mGlowAnim;
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
        mPaintText.setTextAlign(Paint.Align.CENTER);
        mPaintText.setFakeBoldText(true);

        mPaintSubText.setTextAlign(Paint.Align.CENTER);
        mPaintSubText.setFakeBoldText(true);

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
            if (mGlowAnim != null) mGlowAnim.cancel();
            startSpeedometerAnimation();
        }
        invalidate();
    }

    private void startPulseAnimation() {
        if (mPulseAnim != null) mPulseAnim.cancel();
        mPulseAnim = ValueAnimator.ofFloat(0f, 1f);
        mPulseAnim.setDuration(1200);
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
        if (mGlowAnim != null) mGlowAnim.cancel();
        mShackleProgress = 0f;
        mLockGlow = 0f;

        mLockAnim = ValueAnimator.ofFloat(0f, 1f);
        mLockAnim.setDuration(700);
        mLockAnim.setInterpolator(new DecelerateInterpolator(1.5f));
        mLockAnim.addUpdateListener(animation -> {
            mShackleProgress = (float) animation.getAnimatedValue();
            invalidate();
        });
        mLockAnim.start();

        // Glow shockwave triggers right as lock snaps
        postDelayed(() -> {
            mGlowAnim = ValueAnimator.ofFloat(1f, 0f);
            mGlowAnim.setDuration(600);
            mGlowAnim.addUpdateListener(animation -> {
                mLockGlow = (float) animation.getAnimatedValue();
                invalidate();
            });
            mGlowAnim.start();
        }, 550);
    }

    public void startSpeedometerAnimation() {
        if (mSpeedAnim != null) mSpeedAnim.cancel();
        mSpeedProgress = 0f;
        mDisplayedSpeed = 0f;

        mSpeedAnim = ValueAnimator.ofFloat(0f, 1f);
        mSpeedAnim.setDuration(1400);
        mSpeedAnim.setInterpolator(new DecelerateInterpolator());
        mSpeedAnim.addUpdateListener(animation -> {
            float val = (float) animation.getAnimatedValue();
            mSpeedProgress = val;
            mDisplayedSpeed = val * 940f;
            invalidate();
        });
        mSpeedAnim.start();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        float w = getWidth();
        float h = getHeight();
        if (w <= 0 || h <= 0) return;

        float cx = w / 2f;
        float cy = h / 2f;

        // Scale factor relative to 500x500 design viewport
        float scale = Math.min(w, h) / 500f;

        canvas.save();
        canvas.translate(cx, cy);
        canvas.scale(scale, scale);

        if (mCurrentMode == MODE_WELCOME) {
            drawWelcomeEmblem(canvas);
        } else if (mCurrentMode == MODE_LOCK) {
            drawLockSnap(canvas);
        } else if (mCurrentMode == MODE_SPEEDOMETER) {
            drawSpeedometerGauge(canvas);
        }

        canvas.restore();
    }

    private void drawWelcomeEmblem(Canvas canvas) {
        float r = 118f;
        float pulse = mPulseProgress;

        // Outer pulsing ring
        mPaintStroke.reset();
        mPaintStroke.setAntiAlias(true);
        mPaintStroke.setStyle(Paint.Style.STROKE);
        mPaintStroke.setColor(COLOR_AMBER);
        mPaintStroke.setAlpha((int) ((0.20f + pulse * 0.18f) * 255));
        mPaintStroke.setStrokeWidth(3.5f);
        canvas.drawCircle(0, 0, r + pulse * 10f, mPaintStroke);

        // Shield contour
        Path path = new Path();
        path.moveTo(0, -80);
        path.quadTo(80, -80, 80, 0);
        path.quadTo(80, 60, 0, 90);
        path.quadTo(-80, 60, -80, 0);
        path.quadTo(-80, -80, 0, -80);
        path.close();

        mPaintFill.reset();
        mPaintFill.setAntiAlias(true);
        mPaintFill.setStyle(Paint.Style.FILL);
        mPaintFill.setColor(Color.argb((int)(0.08f * 255), 245, 158, 11));
        canvas.drawPath(path, mPaintFill);

        mPaintStroke.setColor(COLOR_AMBER);
        mPaintStroke.setAlpha(255);
        mPaintStroke.setStrokeWidth(4f);
        mPaintStroke.setStrokeCap(Paint.Cap.ROUND);
        mPaintStroke.setStrokeJoin(Paint.Join.ROUND);
        canvas.drawPath(path, mPaintStroke);

        // Center Title "AEGS"
        mPaintText.setTextSize(44f);
        mPaintText.setColor(0xFFFFFFFF);
        canvas.drawText("AEGS", 0, -6, mPaintText);

        // Badge "TITAN v6.0"
        mPaintSubText.setTextSize(16f);
        mPaintSubText.setColor(COLOR_AMBER);
        canvas.drawText("TITAN v6.0", 0, 34, mPaintSubText);
    }

    private void drawLockSnap(Canvas canvas) {
        // Drop distance: 48 units as in design prototype
        float shackleDrop = 48f * mShackleProgress;

        // Shackle Path: Semi-circle arc at top + two straight vertical legs going INTO lock body!
        Path shacklePath = new Path();
        RectF arcRect = new RectF(-46f, -110f + shackleDrop, 46f, -18f + shackleDrop);
        // Top semi-circle from 180 (left) to 0 (right)
        shacklePath.arcTo(arcRect, 180f, 180f, false);
        // Right vertical leg down into body
        shacklePath.lineTo(46f, 6f);
        // Left vertical leg down into body
        shacklePath.moveTo(-46f, -64f + shackleDrop);
        shacklePath.lineTo(-46f, 6f);

        mPaintStroke.reset();
        mPaintStroke.setAntiAlias(true);
        mPaintStroke.setStyle(Paint.Style.STROKE);
        mPaintStroke.setColor(COLOR_SHACKLE);
        mPaintStroke.setStrokeWidth(15f);
        mPaintStroke.setStrokeCap(Paint.Cap.ROUND);
        canvas.drawPath(shacklePath, mPaintStroke);

        // Lock Body: Rounded Rectangle 144 x 115, corner 22
        RectF bodyRect = new RectF(-72f, -8f, 72f, 107f);
        mPaintFill.reset();
        mPaintFill.setAntiAlias(true);
        mPaintFill.setStyle(Paint.Style.FILL);
        mPaintFill.setColor(COLOR_OBSIDIAN_BODY);
        canvas.drawRoundRect(bodyRect, 22f, 22f, mPaintFill);

        // Lock Body Amber Border
        mPaintStroke.setColor(COLOR_AMBER);
        mPaintStroke.setStrokeWidth(3.5f);
        canvas.drawRoundRect(bodyRect, 22f, 22f, mPaintStroke);

        // Amber Keyhole Circle
        mPaintFill.setColor(COLOR_AMBER);
        canvas.drawCircle(0, 34f, 11f, mPaintFill);

        // Amber Keyhole Trapezoid
        Path keySlot = new Path();
        keySlot.moveTo(-6f, 38f);
        keySlot.lineTo(-9f, 68f);
        keySlot.lineTo(9f, 68f);
        keySlot.lineTo(6f, 38f);
        keySlot.close();
        canvas.drawPath(keySlot, mPaintFill);

        // Shockwave glow on snap
        if (mLockGlow > 0f) {
            mPaintStroke.setColor(COLOR_AMBER);
            mPaintStroke.setStrokeWidth(5f * mLockGlow);
            mPaintStroke.setAlpha((int) (mLockGlow * 0.45f * 255));
            canvas.drawCircle(0, 50f, 110f * (1f - mLockGlow * 0.5f), mPaintStroke);
        }
    }

    private void drawSpeedometerGauge(Canvas canvas) {
        float r = 135f;
        RectF arcRect = new RectF(-r, -r, r, r);

        // Inactive background track (135 deg to 405 deg)
        mPaintStroke.reset();
        mPaintStroke.setAntiAlias(true);
        mPaintStroke.setStyle(Paint.Style.STROKE);
        mPaintStroke.setStrokeCap(Paint.Cap.ROUND);
        mPaintStroke.setColor(COLOR_TRACK);
        mPaintStroke.setStrokeWidth(18f);
        canvas.drawArc(arcRect, 135f, 270f, false, mPaintStroke);

        // Active Amber Sweep Arc
        mPaintStroke.setColor(COLOR_AMBER);
        float sweep = 270f * mSpeedProgress;
        canvas.drawArc(arcRect, 135f, sweep, false, mPaintStroke);

        // 10 radial tick marks
        for (int i = 0; i <= 9; i++) {
            float angleDeg = 135f + (i * (270f / 9f));
            double rad = Math.toRadians(angleDeg);
            float x1 = (float) (Math.cos(rad) * (r - 22f));
            float y1 = (float) (Math.sin(rad) * (r - 22f));
            float x2 = (float) (Math.cos(rad) * (r - 10f));
            float y2 = (float) (Math.sin(rad) * (r - 10f));

            boolean isActive = (i / 9f) <= mSpeedProgress;
            mPaintStroke.setColor(isActive ? COLOR_AMBER : COLOR_TICK_INACTIVE);
            mPaintStroke.setStrokeWidth(3f);
            canvas.drawLine(x1, y1, x2, y2, mPaintStroke);
        }

        // Pointer Needle
        double needleRad = Math.toRadians(135f + sweep);
        float nx = (float) (Math.cos(needleRad) * (r - 14f));
        float ny = (float) (Math.sin(needleRad) * (r - 14f));
        mPaintStroke.setColor(COLOR_AMBER);
        mPaintStroke.setStrokeWidth(7f);
        canvas.drawLine(0, 0, nx, ny, mPaintStroke);

        // Center hub
        mPaintFill.reset();
        mPaintFill.setAntiAlias(true);
        mPaintFill.setStyle(Paint.Style.FILL);
        mPaintFill.setColor(COLOR_AMBER);
        canvas.drawCircle(0, 0, 14f, mPaintFill);
        mPaintFill.setColor(0xFFFFFFFF);
        canvas.drawCircle(0, 0, 6f, mPaintFill);

        // Speed numeric text
        mPaintText.setTextSize(42f);
        mPaintText.setColor(0xFFFFFFFF);
        canvas.drawText(String.valueOf(Math.round(mDisplayedSpeed)), 0, 55f, mPaintText);

        // Speed subtitle
        mPaintSubText.setTextSize(15f);
        mPaintSubText.setColor(COLOR_AMBER);
        canvas.drawText("Мбит/с (LTO Turbo)", 0, 82f, mPaintSubText);
    }
}
