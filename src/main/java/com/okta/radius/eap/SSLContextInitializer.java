package com.okta.radius.eap;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;

/**
 * Created by nandagopal.seshagiri on 9/5/18.
 */
public class SSLContextInitializer {
    private SSLContext sslc;

    public SSLContextInitializer(String trustStoreFile, String keyStoreFile, String passwd) {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            KeyStore ts = KeyStore.getInstance("JKS");

            char[] passphrase = passwd.toCharArray();

            ks.load(new FileInputStream(keyStoreFile), passphrase);
            ts.load(new FileInputStream(trustStoreFile), passphrase);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, passphrase);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            SSLContext sslCtx = SSLContext.getInstance("SSLv3");

            sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            sslc = sslCtx;
        } catch (java.security.GeneralSecurityException | IOException e) {
            throw new RuntimeException("Exception while initializing SSLContext", e);
        }
    }

    public SSLContext getSslc() {
        return sslc;
    }
}
