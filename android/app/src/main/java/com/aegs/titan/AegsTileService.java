package com.aegs.titan;

import android.content.Intent;
import android.graphics.drawable.Icon;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import androidx.annotation.RequiresApi;

@RequiresApi(api = Build.VERSION_CODES.N)
public class AegsTileService extends TileService {
    private static boolean sIsConnected = false;

    public static void updateTileState(boolean connected) {
        sIsConnected = connected;
    }

    @Override
    public void onStartListening() {
        super.onStartListening();
        updateTile();
    }

    @Override
    public void onClick() {
        super.onClick();
        Tile tile = getQsTile();
        if (tile == null) return;

        if (!sIsConnected) {
            Intent vpnIntent = VpnService.prepare(this);
            if (vpnIntent != null) {
                Intent appIntent = new Intent(this, MainActivity.class);
                appIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivityAndCollapse(appIntent);
            } else {
                Intent intent = new Intent(this, AegsVpnService.class);
                intent.putExtra("SERVER_IP", "185.196.8.10");
                intent.putExtra("SERVER_PORT", 50001);
                intent.putExtra("TOKEN", "aegs_secure_token_titan_v6");
                startService(intent);
                sIsConnected = true;
                updateTile();
            }
        } else {
            Intent intent = new Intent(this, AegsVpnService.class);
            intent.setAction("STOP");
            startService(intent);
            sIsConnected = false;
            updateTile();
        }
    }

    private void updateTile() {
        Tile tile = getQsTile();
        if (tile != null) {
            tile.setState(sIsConnected ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
            tile.setLabel(sIsConnected ? "AEGS: Вкл" : "AEGS VPN");
            tile.updateTile();
        }
    }
}
