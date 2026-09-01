package com.lyd.player;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public class MainActivity extends AppCompatActivity implements LocalProxyServer.Listener {
    private LocalProxyServer proxy;
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

        proxy = new LocalProxyServer(this, this);

        toggleButton.setOnClickListener(v -> {
            if (proxy.isRunning()) {
                proxy.stop();
                toggleButton.setText("启动代理");
                statusText.setText("代理已停止");
            } else {
                startProxy();
            }
        });

        startProxy();
    }

    private void startProxy() {
        try {
            proxy.start();
            toggleButton.setText("停止代理");
            statusText.setText("代理运行中 127.0.0.1:" + LocalProxyServer.PORT);
        } catch (Exception e) {
            Toast.makeText(this, "启动失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public void onM3u8(final String url) {
        runOnUiThread(() -> {
            statusText.setText("已抓到 m3u8，正在播放...");
            Intent i = new Intent(MainActivity.this, PlayerActivity.class);
            i.putExtra(PlayerActivity.EXTRA_URL, url);
            startActivity(i);
        });
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

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (proxy != null) {
            proxy.stop();
        }
    }
}
