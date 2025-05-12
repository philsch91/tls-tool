package com.schunker.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class SSLTrustManagerHelper {
    private String keyStore;
    private String keyStorePassword;
    private String trustStore;
    private String trustStorePassword;

    public SSLTrustManagerHelper(String keyStore,
                                 String keyStorePassword) {
        this(keyStore, keyStorePassword, null, null);
    }

    public SSLTrustManagerHelper(String keyStore,
                                 String keyStorePassword,
                                 String trustStore,
                                 String trustStorePassword) {
        if (this.isBlank(keyStore) || this.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("KeyStore details are empty, which are required to be present when SSL is enabled");
        }

        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword;
        this.trustStore = trustStore;
        this.trustStorePassword = trustStorePassword;
    }

    public void setTrustStorePath(String trustStorePath) {
        if (this.isBlank(trustStorePath)) {
            throw new IllegalArgumentException("Truststore path must not be null or empty");
        }
        this.trustStore = trustStorePath;
    }

    public String getTrustStorePath() {
        return this.trustStore;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        if (this.isBlank(trustStorePassword)) {
            throw new IllegalArgumentException("Truststore password must not be null or empty");
        }
        this.trustStorePassword = trustStorePassword;
    }

    public String getTrustStorePassword() {
        return this.trustStorePassword;
    }

    public SSLContext getSSLContext() throws Exception {
        try {
            KeyManagerFactory keyManagerFactory = getKeyManagerFactory(this.keyStore, this.keyStorePassword);
            TrustManagerFactory trustManagerFactory = getTrustManagerFactory(this.trustStore, this.trustStorePassword);

            return initSSLContext(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers());
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException | KeyManagementException ex) {
            throw ex;
            //throw new RuntimeException(ex.getCause());
        }
    }

    private static SSLContext initSSLContext(KeyManager[] keyManagers, TrustManager[] trustManagers) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(keyManagers, trustManagers, null);
        return sslContext;
    }

    private static KeyStore loadKeyStore(String keystorePath, String keystorePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        /*
        try (InputStream keystoreInputStream = SSLTrustManagerHelper.class.getClassLoader().getResourceAsStream(keystorePath)) {
            if (keystoreInputStream == null) {
                throw new KeyStoreException(String.format("Could not find the keystore file with the given location %s", keystorePath));
            }

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(keystoreInputStream, keystorePassword.toCharArray());
            return keystore;
        }
        */
        File keystoreFile = new File(keystorePath);
        InputStream keystoreInputStream = new FileInputStream(keystoreFile);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(keystoreInputStream, keystorePassword.toCharArray());

        keystoreInputStream.close();
        return keystore;
    }

    private static KeyManagerFactory getKeyManagerFactory(String keystorePath, String keystorePassword) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyStore keyStore = loadKeyStore(keystorePath, keystorePassword);
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
        return keyManagerFactory;
    }

    private static TrustManagerFactory getTrustManagerFactory(String truststorePath, String truststorePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore trustStore = null;
        if (truststorePath != null && truststorePassword != null) {
            trustStore = loadKeyStore(truststorePath, truststorePassword);
        }
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        return trustManagerFactory;
    }

    private boolean isBlank(String str) {
        if (str == null || str.isEmpty()) {
            return true;
        }
        return false;
    }
}
