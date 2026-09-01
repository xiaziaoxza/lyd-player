package com.lyd.player;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public class MainActivity extends AppCompatActivity implements LocalProxyServer.LogSink {
    private TextView statusText;
    private TextView logText;
    private Button toggleButton;

    static {
        // 信任所有证书：本 App 的 ExoPlayer 经自身代理 MITM（自签证书）时仍能握手成功
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{TrustAll.TRUST_MANAGER}, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(TrustAll.VERIFIER);
        } catch (Exception ignored) {
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.status_text);
        logText = findViewById(R.id.log_text);
        toggleButton = findViewById(R.id.toggle_button);

        toggleButton.setOnClickListener(v -> {
            if (isProxyRunning()) {
                stopProxy();
            } else {
                startProxy();
            }
        });

        // 已在前台服务中运行则同步状态
        if (isProxyRunning()) {
            onProxyStarted();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        ProxyService.setUiLogSink(this);
        refreshLastUrl();
        if (isProxyRunning()) {
            onProxyStarted();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        ProxyService.setUiLogSink(null);
    }

    private boolean isProxyRunning() {
        LocalProxyServer p = ProxyService.getProxy();
        return p != null && p.isRunning();
    }

    private void startProxy() {
        Intent i = new Intent(this, ProxyService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(i);
        } else {
            startService(i);
        }
        onProxyStarted();
    }

    private void stopProxy() {
        stopService(new Intent(this, ProxyService.class));
        toggleButton.setText("启动代理");
        statusText.setText("代理已停止");
    }

    private void onProxyStarted() {
        toggleButton.setText("停止代理");
        statusText.setText("代理运行中 127.0.0.1:" + LocalProxyServer.PORT);
    }

    private void refreshLastUrl() {
        String url = ProxyService.getLastM3u8();
        if (url != null) {
            statusText.setText("已抓到 m3u8，点通知或重进播放");
        }
    }

    @Override
    public void onLog(final String msg) {
        runOnUiThread(() -> {
            String s = msg + "\n" + logText.getText().toString();
            if (s.length() > 2000) {
                s = s.substring(0, 2000);
            }
            logText.setText(s);
        });
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }
}
