package com.aegs.titan;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.View;

import androidx.annotation.Nullable;

/**
 * Clean, subtle ambient background with zero CPU churn and hardware acceleration.
 * Renders an elegant, deep obsidian vignette with a subtle warm central glow.
 * No corner artifacts or distracting bright spots.
 */
public class WaveCirclesBackgroundView extends View {

    private final Paint mGlowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private static class StaticPoint {
        final float rx, ry, r;
        final int color;
        StaticPoint(float rx, float ry, float r, int color) {
            this.rx = rx;
            this.ry = ry;
            this.r = r;
            this.color = color;
        }
    }

    // Centered, balanced ambient glow points - NO artifacts in the corners!
    private final StaticPoint[] mPoints = new StaticPoint[]{
            new StaticPoint(0.50f, 0.40f, 240f, Color.argb(20, 245, 158, 11)),
            new StaticPoint(0.50f, 0.70f, 200f, Color.argb(15, 217, 119, 6))
    };

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
        setLayerType(LAYER_TYPE_HARDWARE, null);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int w = getWidth();
        int h = getHeight();
        if (w <= 0 || h <= 0) return;

        for (StaticPoint pt : mPoints) {
            float cx = pt.rx * w;
            float cy = pt.ry * h;

            RadialGradient grad = new RadialGradient(
                    cx, cy, pt.r,
                    pt.color, Color.TRANSPARENT,
                    Shader.TileMode.CLAMP
            );
            mGlowPaint.setShader(grad);
            canvas.drawCircle(cx, cy, pt.r, mGlowPaint);
        }
    }
}
