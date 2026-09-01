package com.lyd.player;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

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

    public interface LogSink {
        void onLog(String msg);
    }

    private final Context context;
    private Listener listener;
    private volatile LogSink logSink;
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

    public void setLogSink(LogSink sink) {
        this.logSink = sink;
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
        if (logSink != null) {
            logSink.onLog(msg);
        }
        if (listener != null) {
            listener.onLog(msg);
        }
    }

    private void handleClient(Socket client) {
        try {
            client.setSoTimeout(60000);
            PushbackInputStream pin = new PushbackInputStream(client.getInputStream(), 64);
            int first = pin.read();
            if (first == -1) {
                closeQuietly(client);
                return;
            }
            // TLS ClientHello (0x16) -> 透明 TLS MITM；否则是 HTTP（CONNECT / 明文 GET）
            if (first == 0x16) {
                handleTransparentTls(client, pin, first);
                return;
            }
            pin.unread(first);
            String header = readHeader(pin);
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

    /** 透明 TLS MITM：客户端直连 443（被 hook 重定向到本代理），发 TLS ClientHello。解析 SNI 拿域名。 */
    private void handleTransparentTls(Socket client, PushbackInputStream pin, int first) {
        SSLSocket clientSsl = null;
        SSLSocket serverSsl = null;
        try {
            // 读完整 ClientHello record
            ByteArrayOutputStream ch = new ByteArrayOutputStream();
            ch.write(first);
            byte[] hdr = new byte[4];
            readFully(pin, hdr);
            ch.write(hdr);
            int recLen = ((hdr[2] & 0xFF) << 8) | (hdr[3] & 0xFF);
            if (recLen <= 0 || recLen > 65535) {
                closeQuietly(client);
                return;
            }
            byte[] body = new byte[recLen];
            readFully(pin, body);
            ch.write(body);
            byte[] clientHello = ch.toByteArray();

            String host = parseSni(clientHello);
            if (host == null || host.isEmpty()) {
                log("透明TLS: 无 SNI，关闭");
                closeQuietly(client);
                return;
            }
            log("透明TLS MITM: " + host);

            SSLContext serverCtx = SelfSignedCert.getServerContext(context);
            clientSsl = wrapServerSsl(serverCtx.getSocketFactory(), client, clientHello);
            clientSsl.setUseClientMode(false);
            clientSsl.setSoTimeout(60000);
            clientSsl.startHandshake();

            serverSsl = (SSLSocket) TrustAll.getContext().getSocketFactory().createSocket(host, 443);
            serverSsl.setSoTimeout(60000);
            serverSsl.startHandshake();

            relay(clientSsl, serverSsl, host);
        } catch (Exception e) {
            log("透明TLS error " + ": " + e);
        } finally {
            closeQuietly(clientSsl);
            closeQuietly(serverSsl);
            closeQuietly(client);
        }
    }

    /** createSocket(Socket, InputStream consumed, boolean) 是 protected，反射调用。 */
    private SSLSocket wrapServerSsl(SSLSocketFactory factory, Socket client, byte[] clientHello) throws Exception {
        Method m = SSLSocketFactory.class.getDeclaredMethod(
                "createSocket", Socket.class, InputStream.class, boolean.class);
        m.setAccessible(true);
        return (SSLSocket) m.invoke(factory, client, new ByteArrayInputStream(clientHello), true);
    }

    private void readFully(InputStream in, byte[] buf) throws Exception {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n == -1) {
                throw new EOFException("unexpected eof");
            }
            off += n;
        }
    }

    /** 从 ClientHello record 解析 SNI 域名（TLS 1.2/1.3 兼容）。 */
    private String parseSni(byte[] ch) {
        int len = ch.length;
        try {
            if (len < 6) {
                return null;
            }
            int pos = 5; // 跳过 record header: type(1)+ver(2)+len(2)
            if (pos + 4 > len) {
                return null;
            }
            int hsType = ch[pos] & 0xFF;
            if (hsType != 0x01) { // 非 ClientHello
                return null;
            }
            pos += 4; // 跳过 handshake type(1)+len(3)
            if (pos + 2 + 32 + 1 > len) {
                return null;
            }
            pos += 2; // client version
            pos += 32; // random
            int sidLen = ch[pos] & 0xFF;
            pos += 1 + sidLen;
            if (pos + 2 > len) {
                return null;
            }
            int csLen = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
            pos += 2 + csLen;
            if (pos + 1 > len) {
                return null;
            }
            int compLen = ch[pos] & 0xFF;
            pos += 1 + compLen;
            if (pos + 2 > len) {
                return null;
            }
            int extLen = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
            pos += 2;
            int extEnd = Math.min(pos + extLen, len);
            while (pos + 4 <= extEnd) {
                int type = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
                int elen = ((ch[pos + 2] & 0xFF) << 8) | (ch[pos + 3] & 0xFF);
                pos += 4;
                if (type == 0x0000) { // SNI
                    if (pos + 2 > len) {
                        return null;
                    }
                    int listLen = ((ch[pos] & 0xFF) << 8) | (ch[pos + 1] & 0xFF);
                    int p = pos + 2;
                    int listEnd = p + listLen;
                    if (p + 3 <= listEnd && p + 3 <= len) {
                        int nameType = ch[p] & 0xFF;
                        int nameLen = ((ch[p + 1] & 0xFF) << 8) | (ch[p + 2] & 0xFF);
                        p += 3;
                        if (nameType == 0 && p + nameLen <= len) {
                            return new String(ch, p, nameLen, "US-ASCII");
                        }
                    }
                    return null;
                }
                pos += elen;
            }
            return null;
        } catch (Exception e) {
            return null;
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
