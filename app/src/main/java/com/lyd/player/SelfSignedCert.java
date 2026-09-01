package com.lyd.player;

import android.content.Context;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/** 从 raw/lyd.p12 加载自签证书，构建 MITM 服务器端 SSLContext（向原 App 出示自签证书）。 */
public class SelfSignedCert {
    private static final char[] PASS = "changeit".toCharArray();
    private static SSLContext serverContext;

    public static synchronized SSLContext getServerContext(Context context) throws Exception {
        if (serverContext != null) {
            return serverContext;
        }
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = context.getResources().openRawResource(R.raw.lyd)) {
            ks.load(is, PASS);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, PASS);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), new TrustManager[]{TrustAll.TRUST_MANAGER}, new SecureRandom());
        serverContext = ctx;
        return ctx;
    }
}
