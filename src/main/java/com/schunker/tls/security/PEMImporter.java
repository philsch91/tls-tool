package com.schunker.tls.security;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;

public class PEMImporter {

    public static SSLServerSocketFactory createSSLFactory(File privateKeyPemFile, File certificatePemFile, String password) throws Exception {
        final SSLContext context = SSLContext.getInstance("TLS");
        final KeyStore keystore = createKeyStore(privateKeyPemFile, certificatePemFile, password);
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX"); // SunX509
        kmf.init(keystore, password.toCharArray());
        final KeyManager[] keyManagers = kmf.getKeyManagers();
        context.init(keyManagers, null, null);
        return context.getServerSocketFactory();
    }

    public static KeyStore createKeyStore(File privateKeyPemFile, File certificatePemFile, final String password)
            throws Exception, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final X509Certificate[] certificates = createCertificates(certificatePemFile);
        final KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(null);
        final PrivateKey privateKey = createPrivateKey(privateKeyPemFile);
        keystore.setKeyEntry(privateKeyPemFile.getName(), privateKey, password.toCharArray(), certificates);
        return keystore;
    }

    public static PrivateKey createPrivateKey(File privateKeyPemFile) throws Exception, IllegalArgumentException {
        final BufferedReader reader = new BufferedReader(new FileReader(privateKeyPemFile));
        String s = reader.readLine();
        if (s != null && s.contains("BEGIN RSA PRIVATE KEY")) {
            reader.close();
            throw new IllegalArgumentException(privateKeyPemFile.getName() + " is a PKCS#1 and not a PKCS#8 key.");
        }
        if (s == null || !s.contains("BEGIN PRIVATE KEY")) {
            reader.close();
            throw new IllegalArgumentException("Expected BEGIN PRIVATE KEY header in " + privateKeyPemFile.getName() + " instead of " + s);
        }
        final StringBuilder builder = new StringBuilder();
        s = "";
        while (s != null) {
            if (s.contains("END PRIVATE KEY")) {
                break;
            }
            builder.append(s);
            s = reader.readLine();
        }
        final String hexString = builder.toString();
        final byte[] bytes = Base64.getDecoder().decode(hexString);
        return generatePrivateKeyFromDER(bytes);
    }

    public static X509Certificate[] createCertificates(File certificatePemFile) throws Exception, IllegalArgumentException {
        final List<X509Certificate> result = new ArrayList<X509Certificate>();
        final BufferedReader reader = new BufferedReader(new FileReader(certificatePemFile));
        String s = reader.readLine();
        if (s == null || !s.contains("BEGIN CERTIFICATE")) {
            reader.close();
            throw new IllegalArgumentException("Expected BEGIN CERTIFICATE header in" + certificatePemFile.getName() + " instead of " + s);
        }
        StringBuilder builder = new StringBuilder();
        while (s != null) {
            if (s.contains("END CERTIFICATE")) {
                String hexString = builder.toString();
                final byte[] bytes = Base64.getDecoder().decode(hexString);
                X509Certificate certificate = generateCertificateFromDER(bytes);
                result.add(certificate);
                builder = new StringBuilder();
            } else {
                if (!s.startsWith("----")) {
                    builder.append(s);
                }
            }
            s = reader.readLine();
        }
        reader.close();
        return result.toArray(new X509Certificate[result.size()]);
    }

    private static RSAPrivateKey generatePrivateKeyFromDER(byte[] privateKeyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        final PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(encodedKeySpec);
    }

    private static X509Certificate generateCertificateFromDER(byte[] certificateBytes) throws CertificateException {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
    }
}
