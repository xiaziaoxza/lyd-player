package com.lyd.player;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * 本地 HTTP 代理：监听 127.0.0.1:8080。
 * - CONNECT 到 API 主站 -> MITM（自签证书），在明文流里检测 /vid/m3u8 请求并提取完整 URL。
 * - CONNECT 到其他 -> 透明隧道转发（CDN、图片等直连，不 MITM）。
 */
public class LocalProxyServer {
    private static final String TAG = "LYDProxy";
    public static final int PORT = 8080;

    public interface Listener {
        void onM3u8(String url);

        void onLog(String msg);
    }

    private final Context context;
    private Listener listener;
    private ServerSocket serverSocket;
    private final AtomicBoolean running = new AtomicBoolean(false);

    // API 主站域名后缀（走 Java 层 HttpsURLConnection，信任所有证书，可 MITM）
    private static final String[] API_SUFFIXES = {
            "julebuhao.com",
            "hxgd688.com",
            "lydkf.shop",
            "lda-stwgah.shop",
            "liufei86.com",
            "jiaodsj.com",
    };

    public LocalProxyServer(Context context, Listener listener) {
        this.context = context;
        this.listener = listener;
    }

    public boolean isRunning() {
        return running.get();
    }

    public void setListener(Listener l) {
        this.listener = l;
    }

    public void start() throws Exception {
        if (running.get()) {
            return;
        }
        serverSocket = new ServerSocket(PORT, 64);
        serverSocket.setReuseAddress(true);
        running.set(true);
        Thread t = new Thread(this::acceptLoop, "proxy-accept");
        t.setDaemon(true);
        t.start();
        log("代理已启动 127.0.0.1:" + PORT);
    }

    public void stop() {
        running.set(false);
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (Exception ignored) {
        }
        serverSocket = null;
        log("代理已停止");
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket client = serverSocket.accept();
                Thread t = new Thread(() -> handleClient(client), "proxy-conn");
                t.setDaemon(true);
                t.start();
            } catch (Exception e) {
                if (running.get()) {
                    log("accept error: " + e);
                }
            }
        }
    }

    private void log(String msg) {
        Log.i(TAG, msg);
        if (listener != null) {
            listener.onLog(msg);
        }
    }

    private void handleClient(Socket client) {
        try {
            client.setSoTimeout(60000);
            String header = readHeader(client.getInputStream());
            if (header == null || header.isEmpty()) {
                closeQuietly(client);
                return;
            }
            String firstLine = header.split("\r\n")[0];
            log("REQ: " + firstLine);
            String[] parts = firstLine.split(" ");
            if (parts.length < 2) {
                closeQuietly(client);
                return;
            }
            String method = parts[0];
            String target = parts[1];

            if ("CONNECT".equalsIgnoreCase(method)) {
                handleConnect(client, target);
            } else if (target.startsWith("http://")) {
                handlePlainHttp(client, method, target, header);
            } else {
                closeQuietly(client);
            }
        } catch (SocketTimeoutException e) {
            closeQuietly(client);
        } catch (Exception e) {
            log("handle error: " + e);
            closeQuietly(client);
        }
    }

    /** 逐字节读取直到 \r\n\r\n，避免缓冲吃掉后续 TLS 握手字节。 */
    private String readHeader(InputStream in) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int b;
        int match = 0;
        while ((b = in.read()) != -1) {
            baos.write(b);
            if (match == 0 && b == '\r') {
                match = 1;
            } else if (match == 1 && b == '\n') {
                match = 2;
            } else if (match == 2 && b == '\r') {
                match = 3;
            } else if (match == 3 && b == '\n') {
                break;
            } else if (b == '\r') {
                match = 1;
            } else {
                match = 0;
            }
        }
        if (baos.size() == 0) {
            return null;
        }
        return new String(baos.toByteArray(), "ISO-8859-1");
    }

    private void handleConnect(Socket client, String target) {
        String[] hp = target.split(":");
        String host = hp[0].trim();
        int port = hp.length > 1 ? parsePort(hp[1]) : 443;
        try {
            OutputStream out = client.getOutputStream();
            out.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes("ISO-8859-1"));
            out.flush();
        } catch (Exception e) {
            closeQuietly(client);
            return;
        }
        boolean api = isApiHost(host);
        log("CONNECT: " + host + ":" + port + " api=" + api);
        if (api) {
            mitm(client, host, port);
        } else {
            tunnel(client, host, port);
        }
    }

    private void handlePlainHttp(Socket client, String method, String target, String header) {
        Socket server = null;
        try {
            URI uri = new URI(target);
            String host = uri.getHost();
            int port = uri.getPort() > 0 ? uri.getPort() : 80;
            server = new Socket(host, port);
            server.setSoTimeout(60000);
            String path = uri.getRawPath() == null ? "/" : uri.getRawPath();
            if (uri.getRawQuery() != null) {
                path += "?" + uri.getRawQuery();
            }
            int firstLineEnd = header.indexOf("\r\n");
            String rest = firstLineEnd >= 0 ? header.substring(firstLineEnd) : "\r\n\r\n";
            OutputStream out = server.getOutputStream();
            out.write((method + " " + path + " HTTP/1.1\r\n").getBytes("ISO-8859-1"));
            out.write(rest.getBytes("ISO-8859-1"));
            out.flush();
            relay(client, server);
        } catch (Exception e) {
            log("plain http error: " + e);
        } finally {
            closeQuietly(server);
            closeQuietly(client);
        }
    }

    private boolean isApiHost(String host) {
        host = host.toLowerCase();
        for (String s : API_SUFFIXES) {
            if (host.equals(s) || host.endsWith("." + s)) {
                return true;
            }
        }
        return false;
    }

    private int parsePort(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return 443;
        }
    }

    private void tunnel(Socket client, String host, int port) {
        Socket server = null;
        try {
            server = new Socket(host, port);
            server.setSoTimeout(60000);
            relay(client, server);
        } catch (Exception e) {
            log("tunnel error " + host + ": " + e);
        } finally {
            closeQuietly(server);
            closeQuietly(client);
        }
    }

    private void mitm(Socket client, String host, int port) {
        SSLSocket clientSsl = null;
        SSLSocket serverSsl = null;
        try {
            SSLContext serverCtx = SelfSignedCert.getServerContext(context);
            clientSsl = (SSLSocket) serverCtx.getSocketFactory().createSocket(client, host, port, true);
            clientSsl.setUseClientMode(false);
            clientSsl.setSoTimeout(60000);
            clientSsl.startHandshake();

            serverSsl = (SSLSocket) TrustAll.getContext().getSocketFactory().createSocket(host, port);
            serverSsl.setSoTimeout(60000);
            serverSsl.startHandshake();

            relay(clientSsl, serverSsl, host);
        } catch (Exception e) {
            log("mitm error " + host + ": " + e);
        } finally {
            closeQuietly(clientSsl);
            closeQuietly(serverSsl);
            closeQuietly(client);
        }
    }

    private void relay(Socket a, Socket b) {
        relay(a, b, null);
    }

    /** 双向转发。inspectHost 非空时在 a->b 方向扫描明文，检测 m3u8 请求。 */
    private void relay(final Socket a, final Socket b, final String inspectHost) {
        final boolean inspect = inspectHost != null;
        final AtomicBoolean closed = new AtomicBoolean(false);
        final Runnable closeBoth = () -> {
            if (closed.compareAndSet(false, true)) {
                closeQuietly(a);
                closeQuietly(b);
            }
        };
        Thread t1 = new Thread(() -> {
            try {
                InputStream in = a.getInputStream();
                OutputStream out = b.getOutputStream();
                byte[] buf = new byte[16384];
                StringBuilder sb = inspect ? new StringBuilder() : null;
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                    out.flush();
                    if (inspect && sb.length() < 65536) {
                        sb.append(new String(buf, 0, n, "ISO-8859-1"));
                        checkForM3u8(sb.toString(), inspectHost);
                    }
                }
            } catch (Exception ignored) {
            } finally {
                closeBoth.run();
            }
        });
        Thread t2 = new Thread(() -> {
            try {
                InputStream in = b.getInputStream();
                OutputStream out = a.getOutputStream();
                byte[] buf = new byte[16384];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                    out.flush();
                }
            } catch (Exception ignored) {
            } finally {
                closeBoth.run();
            }
        });
        t1.setDaemon(true);
        t2.setDaemon(true);
        t1.start();
        t2.start();
        try {
            t1.join();
        } catch (InterruptedException ignored) {
        }
        try {
            t2.join();
        } catch (InterruptedException ignored) {
        }
    }

    private String lastUrl = null;
    private long lastNotifyTime = 0;

    private void checkForM3u8(String data, String host) {
        int idx = data.indexOf("/vid/m3u8");
        if (idx < 0) {
            return;
        }
        int lineStart = data.lastIndexOf("GET ", idx);
        if (lineStart < 0) {
            lineStart = data.lastIndexOf("POST ", idx);
        }
        if (lineStart < 0) {
            return;
        }
        int pathStart = lineStart + 4;
        int pathEnd = data.indexOf(" ", pathStart);
        if (pathEnd < 0 || pathEnd <= pathStart) {
            return;
        }
        String path = data.substring(pathStart, pathEnd);
        if (!path.contains("/vid/m3u8")) {
            return;
        }
        String url = "https://" + host + path;
        long now = System.currentTimeMillis();
        synchronized (this) {
            if (url.equals(lastUrl) && now - lastNotifyTime < 2000) {
                return;
            }
            lastUrl = url;
            lastNotifyTime = now;
        }
        log("抓到 m3u8: " + url);
        if (listener != null) {
            listener.onM3u8(url);
        }
    }

    private void closeQuietly(Closeable c) {
        try {
            if (c != null) {
                c.close();
            }
        } catch (Exception ignored) {
        }
    }
}
