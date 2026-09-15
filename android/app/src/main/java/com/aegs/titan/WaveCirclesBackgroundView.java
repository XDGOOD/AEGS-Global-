package com.aegs.titan;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.LinearInterpolator;

import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class WaveCirclesBackgroundView extends View {

    private static final int NUM_CIRCLES = 15;

    private static class Circle {
        float x, y;
        float vx, vy;
        float r, baseR;
        int colorIdx;
    }

    private final List<Circle> mCircles = new ArrayList<>();
    private final Paint mFillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint mStrokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private final int[] mFills = new int[]{
            Color.argb((int)(0.22f * 255), 245, 158, 11),  // Amber
            Color.argb((int)(0.16f * 255), 251, 146, 60),  // Orange
            Color.argb((int)(0.14f * 255), 217, 119, 6),   // Deep amber
            Color.argb((int)(0.07f * 255), 255, 255, 255)  // White subtle
    };

    private final int[] mStrokes = new int[]{
            Color.argb((int)(0.40f * 255), 245, 158, 11),
            Color.argb((int)(0.32f * 255), 251, 146, 60),
            Color.argb((int)(0.30f * 255), 217, 119, 6),
            Color.argb((int)(0.18f * 255), 255, 255, 255)
    };

    private ValueAnimator mAnimator;

    public WaveCirclesBackgroundView(Context context) {
        super(context);
        init();
    }

    public WaveCirclesBackgroundView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public WaveCirclesBackgroundView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        mFillPaint.setStyle(Paint.Style.FILL);
        mStrokePaint.setStyle(Paint.Style.STROKE);
        mStrokePaint.setStrokeWidth(2.5f);

        Random rnd = new Random();
        for (int i = 0; i < NUM_CIRCLES; i++) {
            Circle c = new Circle();
            c.r = 30f + rnd.nextFloat() * 60f;
            c.baseR = c.r;
            c.vx = (rnd.nextFloat() - 0.5f) * 1.2f;
            c.vy = (rnd.nextFloat() - 0.5f) * 1.2f;
            c.colorIdx = i % 4;
            mCircles.add(c);
        }

        mAnimator = ValueAnimator.ofFloat(0f, 1f);
        mAnimator.setDuration(1000);
        mAnimator.setRepeatCount(ValueAnimator.INFINITE);
        mAnimator.setInterpolator(new LinearInterpolator());
        mAnimator.addUpdateListener(animation -> invalidate());
    }

    @Override
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (mAnimator != null && !mAnimator.isStarted()) {
            mAnimator.start();
        }
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (mAnimator != null) {
            mAnimator.cancel();
        }
    }

    @Override
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        Random rnd = new Random();
        for (Circle c : mCircles) {
            c.x = c.r + rnd.nextFloat() * (w - c.r * 2);
            c.y = c.r + rnd.nextFloat() * (h - c.r * 2);
        }
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int w = getWidth();
        int h = getHeight();
        if (w <= 0 || h <= 0) return;

        for (Circle c : mCircles) {
            c.x += c.vx;
            c.y += c.vy;

            if (c.x < c.r) { c.x = c.r; c.vx *= -1; }
            else if (c.x > w - c.r) { c.x = w - c.r; c.vx *= -1; }

            if (c.y < c.r) { c.y = c.r; c.vy *= -1; }
            else if (c.y > h - c.r) { c.y = h - c.r; c.vy *= -1; }

            mFillPaint.setColor(mFills[c.colorIdx]);
            mStrokePaint.setColor(mStrokes[c.colorIdx]);

            canvas.drawCircle(c.x, c.y, c.r, mFillPaint);
            canvas.drawCircle(c.x, c.y, c.r, mStrokePaint);
        }
    }
}
