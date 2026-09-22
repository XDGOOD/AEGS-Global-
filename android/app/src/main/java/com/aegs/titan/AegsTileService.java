package com.aegs.titan;

import android.content.Intent;
import android.content.SharedPreferences;
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
                SharedPreferences prefs = getSharedPreferences("aegs_prefs", MODE_PRIVATE);
                String host = prefs.getString("server_ip", "31.76.9.86");
                int port = prefs.getInt("server_port", 50001);
                String token = prefs.getString("token", "aegs_secure_token_titan_v6");
                int proto = prefs.getInt("protocol_mode", 0);
                boolean chaff = prefs.getBoolean("adaptive_chaff", true);

                Intent intent = new Intent(this, AegsVpnService.class);
                intent.putExtra("SERVER_IP", host);
                intent.putExtra("SERVER_PORT", port);
                intent.putExtra("TOKEN", token);
                intent.putExtra("PROTOCOL_MODE", proto);
                intent.putExtra("ADAPTIVE_CHAFF", chaff);
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
            tile.setLabel(sIsConnected ? "AEGS: ON" : "AEGS VPN");
            tile.updateTile();
        }
    }
}
