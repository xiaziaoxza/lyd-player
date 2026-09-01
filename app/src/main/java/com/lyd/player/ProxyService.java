package com.lyd.player;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

/**
 * 前台服务：持有 LocalProxyServer 单例并保活，避免 App 切后台后被 cgroup 冻结导致 accept 停摆。
 * 抓到 m3u8 后：存静态字段 + 更新通知（点通知即用 ExoPlayer 播放）+ 尝试直接拉起播放页。
 */
public class ProxyService extends Service implements LocalProxyServer.Listener {
    private static final String CHANNEL_ID = "lyd_proxy";
    private static final int NOTIF_ID = 1;

    private static LocalProxyServer proxy;
    private static String lastM3u8;
    private static LocalProxyServer.LogSink uiLogSink;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
        startForegroundCompat(NOTIF_ID, buildNotification(null));
        if (proxy == null) {
            proxy = new LocalProxyServer(getApplicationContext(), this);
        } else {
            proxy.setListener(this);
        }
        try {
            proxy.start();
        } catch (Exception e) {
            stopSelf();
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onM3u8(String url) {
        lastM3u8 = url;
        // 更新通知：点通知直接播放
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.notify(NOTIF_ID, buildNotification(url));
        // 尝试直接拉起播放页（App 前台时能成功；后台则靠用户点通知）
        try {
            Intent i = new Intent(this, PlayerActivity.class);
            i.putExtra(PlayerActivity.EXTRA_URL, url);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
        } catch (Exception ignored) {
        }
    }

    @Override
    public void onLog(String msg) {
        // 转发给 MainActivity（若在）显示；日志本身已由 LocalProxyServer 写 Log.i
        if (uiLogSink != null) {
            uiLogSink.onLog(msg);
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (proxy != null) {
            proxy.stop();
        }
    }

    public static LocalProxyServer getProxy() {
        return proxy;
    }

    public static String getLastM3u8() {
        return lastM3u8;
    }

    public static void setUiLogSink(LocalProxyServer.LogSink sink) {
        uiLogSink = sink;
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(CHANNEL_ID, "代理服务", NotificationManager.IMPORTANCE_LOW);
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            nm.createNotificationChannel(ch);
        }
    }

    private void startForegroundCompat(int id, Notification n) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(id, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(id, n);
        }
    }

    private Notification buildNotification(String url) {
        Intent target;
        String text;
        if (url != null) {
            target = new Intent(this, PlayerActivity.class);
            target.putExtra(PlayerActivity.EXTRA_URL, url);
            text = "已抓到视频，点此播放";
        } else {
            target = new Intent(this, MainActivity.class);
            text = "正在抓取 m3u8…";
        }
        PendingIntent pi = PendingIntent.getActivity(this, 0, target,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_launcher)
                .setContentTitle("LYD 代理运行中")
                .setContentText(text)
                .setOngoing(true)
                .setContentIntent(pi)
                .build();
    }
}
