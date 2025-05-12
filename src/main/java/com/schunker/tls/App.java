package com.schunker.tls;

import java.security.*;
import java.util.Enumeration;

import java.net.URL;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.InetSocketAddress;
import java.net.URLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.lang.reflect.Field;

import com.schunker.java.*;
import com.schunker.tls.net.HttpsURLConnectionWrapper;

public class App {

    private static final String KEYSTORE_TYPE_DEFAULT = KeyStore.getDefaultType();
    private static final String KEYSTORE_TYPE_JCEKS = "jceks";
    private static final String KEYSTORE_TYPE_DKS = "dks";
    private static final String KEYSTORE_TYPE_PKCS11 = "pkcs11";
    private static final String KEYSTORE_TYPE_PKCS12 = "pkcs12";

    public static void main(String[] args) {
        App app = new App();
        try {
            app.init();
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }

    public void init() throws Exception {
        Menu menu = new Menu();
        menu.setTitle("TLS Tool");
        menu.insert("Test TLS (mTLS) connection");
        menu.insert("Create Java keystore");
        menu.insert("Edit Java keystore");
        menu.insert("Compare Java keystores");
        int inputOption = menu.show();

        if (inputOption == 1) {
            this.testConnection();
        } else if (inputOption == 2) {
            this.createKeystore();
        } else if (inputOption == 3) {
            this.editKeystore();
        } else if (inputOption == 4) {
            this.compareKeystores();
        }
    }

    private void testConnection() {
        TextBox urlTextBox = new TextBox("URL", TextBoxInputType.TEXT);
        String urlString = urlTextBox.show();

        if (!urlString.startsWith("https://")) {
            System.out.println("URL must start with 'https://'");
            return;
        }

        System.out.println("URL: " + urlString);

        TextBox keystorePathTextBox = new TextBox("Keystore path", TextBoxInputType.TEXT);
        String keystorePath = keystorePathTextBox.show();
        System.out.println("Keystore path: [" + keystorePath + "]");

        TextBox keystorePasswordTextBox = new TextBox("Keystore password", TextBoxInputType.TEXT);
        String keystorePassword = keystorePasswordTextBox.show();
        System.out.println("Keystore password: [" + keystorePassword + "]");

        TextBox truststorePathTextBox = new TextBox("Truststore path", TextBoxInputType.TEXT);
        String truststorePath = truststorePathTextBox.show();
        System.out.println("Truststore path: [" + truststorePath + "]");

        TextBox truststorePasswordTextBox = new TextBox("Truststore password", TextBoxInputType.TEXT);
        String truststorePassword = truststorePasswordTextBox.show();
        System.out.println("Truststore password: [" + truststorePassword + "]");

        SSLTrustManagerHelper trustManagerHelper = new SSLTrustManagerHelper(keystorePath, keystorePassword);

        //System.setProperty("javax.net.ssl.trustStore", truststorePath);
        //System.setProperty("javax.net.ssl.trustStorePassword", truststorePassword);

        if (!truststorePath.isEmpty()) {
            trustManagerHelper.setTrustStorePath(truststorePath);
        }
        if (!truststorePassword.isEmpty()) {
            trustManagerHelper.setTrustStorePassword(truststorePassword);
        }

        SSLContext sslContext = null;

        try {
            sslContext = trustManagerHelper.getSSLContext();
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }

        URL url = null;

        try {
            url = new URL(urlString);
        } catch (MalformedURLException ex) {
            System.err.println("Malformed URL: " + urlString);
            System.err.println(ex.getMessage());
            ex.printStackTrace();
            System.exit(2);
        }
        
        Proxy proxy = null;

        if (System.getenv("HTTPS_PROXY") != null && System.getenv("PROXY_PORT") != null) {
            String proxyHostname = System.getenv("HTTPS_PROXY");
            int proxyPort = Integer.parseInt(System.getenv("PROXY_PORT"));
            proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHostname, proxyPort));
        } else {
            proxy = Proxy.NO_PROXY;
        }

        //HttpsURLConnection urlConnection = null;
        HttpsURLConnectionWrapper urlConnectionWrapper = null;

        try {
            //urlConnection = (HttpsURLConnection) url.openConnection(proxy);
            //urlConnection.setRequestMethod("GET");
            urlConnectionWrapper = new HttpsURLConnectionWrapper(url, proxy);
            urlConnectionWrapper.urlConnection.setRequestMethod("GET");
        } catch (Exception ex) {
            System.err.println("Exception for opening (creating) connection");
            System.err.println(ex.getMessage());
            ex.printStackTrace();
            System.exit(3);
        }

        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        urlConnectionWrapper.urlConnection.setSSLSocketFactory(sslSocketFactory);
        urlConnectionWrapper.urlConnection.setConnectTimeout(10 * 1000);
        urlConnectionWrapper.setDefaultRequestParameters();

        if (System.getProperty("ssl.SocketFactory.provider", "default").equals("WireLogSSLSocketFactory")) {
            System.out.println("Use WireLogSSLSocketFactory");
            //sslSocketFactory = new WireLogSSLSocketFactory(sslSocketFactory);
            WireLogSSLSocketFactory wireLogSSLSocketFactory = new WireLogSSLSocketFactory(sslSocketFactory);
            urlConnectionWrapper.urlConnection.setSSLSocketFactory(wireLogSSLSocketFactory);
        }

        //urlConnectionWrapper.urlConnection.setSSLSocketFactory(sslSocketFactory);

        /*
        List<Field> fields = ReflectionHelper.getDeclaredFields(urlConnection.getClass());
        for (Field field : fields) {
            System.out.println("URLConnection field: " + field.toString());
        } */

        //boolean isConnected = this.isConnectionConnected(urlConnection);
        //System.out.println("HttpsURLConnection.connected: " + isConnected);

        try {
            urlConnectionWrapper.urlConnection.connect();
        } catch (SSLHandshakeException sslex) {
            System.err.println("Exception for connecting via TLS");
            System.err.println(sslex.getMessage());
            sslex.printStackTrace();
            System.exit(4);
        } catch (Exception ex) {
            System.err.println("Exception for connecting connection");
            System.err.println(ex.getMessage());
            ex.printStackTrace();
            System.exit(4);
        }

        //isConnected = this.isConnectionConnected(urlConnection);
        //System.out.println("HttpsURLConnection.connected: " + isConnected);

        int responseCode = 0;

        try {
            responseCode = urlConnectionWrapper.urlConnection.getResponseCode();
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
            ex.printStackTrace();
            System.exit(5);
        }

        System.out.println("Response code: " + Integer.toString(responseCode));

        String content = null;

        try {
            //content = urlConnectionWrapper.urlConnection.getContent().toString();
            content = urlConnectionWrapper.getResponseContent();
        } catch (IOException ex) {
            System.err.println(ex.getMessage());
            ex.printStackTrace();
            System.exit(6);
        }

        System.out.println("Content: " + content);

        /*
        String responseMessage = null;

        try {
            responseMessage = urlConnection.getResponseMessage();
        } catch (IOException ex) {
            System.err.println(ex.getMessage());
            System.exit(7);
        }

        System.out.println("Response message: " + responseMessage);
        */

        String responseBody = urlConnectionWrapper.getResponseBody();
        System.out.println("Response body: " + responseBody);
    }

    private void createKeystore() throws IOException {
        System.out.println("Option not completely implemented");

        TextBox keystorePathTextBox = new TextBox("Keystore (Truststore) path", TextBoxInputType.TEXT);
        String keystorePath = keystorePathTextBox.show();
        System.out.println("Keystore path: [" + keystorePath + "]");

        // TODO: check for existing file

        TextBox keystorePasswordTextBox = new TextBox("Keystore password", TextBoxInputType.TEXT);
        String keystorePassword = keystorePasswordTextBox.show();
        System.out.println("Keystore password: [" + keystorePassword + "]");

        TextBox keystoreTypeTextBox = new TextBox("Keystore (Truststore) type", TextBoxInputType.TEXT);
        String keystoreType = keystoreTypeTextBox.show();
        System.out.println("Keystore type: " + keystoreType);

        if (keystoreType.isEmpty()) {
            keystoreType = KEYSTORE_TYPE_DEFAULT;
            System.out.println("Use keystore default type " + keystoreType);
        }

        KeyStore keystore;

        try {
            keystore = KeyStore.getInstance(keystoreType);
            keystore.load(null, keystorePassword.toCharArray());
        } catch (Exception ex) {
            System.err.println("Exception message: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
            return;
        }

        FileOutputStream fos = null;
        boolean error = false;

        try {
            //File file = new File(keystorePath);
            //keystore.store(file, keystorePassword.toCharArray());
            fos = new FileOutputStream(keystorePath);
            keystore.store(fos, keystorePassword.toCharArray());
        } catch (Exception ex) {
            System.err.println("Exception message: " + ex.getMessage());
            ex.printStackTrace();
            error = true;
        } finally {
            if (fos != null) {
                fos.close();
            }
        }

        if (error) {
            System.exit(1);
        }
    }

    private void editKeystore() throws IOException {
        TextBox keystorePathTextBox = new TextBox("Keystore (Truststore) path", TextBoxInputType.TEXT);
        String keystorePath = keystorePathTextBox.show();
        System.out.println("Keystore path: [" + keystorePath + "]");

        // TODO: check for existing file

        TextBox keystorePasswordTextBox = new TextBox("Keystore password", TextBoxInputType.TEXT);
        String keystorePassword = keystorePasswordTextBox.show();
        System.out.println("Keystore password: [" + keystorePassword + "]");

        TextBox keystoreTypeTextBox = new TextBox("Keystore (Truststore) type", TextBoxInputType.TEXT);
        String keystoreType = keystoreTypeTextBox.show();
        System.out.println("Keystore type: " + keystoreType);

        if (keystoreType.isEmpty()) {
            keystoreType = KEYSTORE_TYPE_DEFAULT;
            System.out.println("Use keystore default type " + keystoreType);
        }

        KeyStore keystore = this.loadKeystore(keystorePath, keystorePassword, keystoreType);

        Enumeration<String> aliases;

        try {
            aliases = keystore.aliases();
        } catch (KeyStoreException kex) {
            System.err.println("Exception message: " + kex.getMessage());
            kex.printStackTrace();
            System.exit(1);
            return;
        }

        int i = 1;
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            // KeyStore.Entry entry;
            String keystoreEntryClassName = "unknown";

            try {
                if (keystore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                    keystoreEntryClassName = KeyStore.PrivateKeyEntry.class.getName();
                } else if (keystore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
                    keystoreEntryClassName = KeyStore.SecretKeyEntry.class.getName();
                } else if (keystore.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
                    keystoreEntryClassName = KeyStore.TrustedCertificateEntry.class.getName();
                }
            } catch (Exception ex) {
                System.err.println("Exception message: " + ex.getMessage());
                ex.printStackTrace();
            }

            System.out.println("Alias " + Integer.toString(i) + ": " + alias + " (" + keystoreEntryClassName + ")");
            i++;
        }
    }

    private void compareKeystores() throws IOException {
        TextBox keystorePathTextBox = new TextBox("Keystore (Truststore) path", TextBoxInputType.TEXT);
        String keystorePath = keystorePathTextBox.show();
        System.out.println("Keystore path: [" + keystorePath + "]");

        // TODO: check for existing file

        TextBox keystorePasswordTextBox = new TextBox("Keystore password", TextBoxInputType.TEXT);
        String keystorePassword = keystorePasswordTextBox.show();
        System.out.println("Keystore password: [" + keystorePassword + "]");

        TextBox keystoreTypeTextBox = new TextBox("Keystore (Truststore) type", TextBoxInputType.TEXT);
        String keystoreType = keystoreTypeTextBox.show();
        System.out.println("Keystore type: " + keystoreType);

        if (keystoreType.isEmpty()) {
            keystoreType = KEYSTORE_TYPE_DEFAULT;
            System.out.println("Use keystore default type " + keystoreType);
        }

        KeyStore keystore = this.loadKeystore(keystorePath, keystorePassword, keystoreType);

        keystorePathTextBox = new TextBox("Keystore (Truststore) path 2", TextBoxInputType.TEXT);
        keystorePath = keystorePathTextBox.show();
        System.out.println("Keystore path: [" + keystorePath + "]");

        // TODO: check for existing file

        keystorePasswordTextBox = new TextBox("Keystore password 2", TextBoxInputType.TEXT);
        keystorePassword = keystorePasswordTextBox.show();
        System.out.println("Keystore password: [" + keystorePassword + "]");

        keystoreTypeTextBox = new TextBox("Keystore (Truststore) type 2", TextBoxInputType.TEXT);
        keystoreType = keystoreTypeTextBox.show();
        System.out.println("Keystore type: " + keystoreType);

        if (keystoreType.isEmpty()) {
            keystoreType = KEYSTORE_TYPE_DEFAULT;
            System.out.println("Use keystore default type " + keystoreType);
        }

        KeyStore keystore2 = this.loadKeystore(keystorePath, keystorePassword, keystoreType);
    }

    private boolean isConnectionConnected(URLConnection urlConnection) {
        System.out.println("isConnectionConnected");
        Field connectedField = null;
        boolean isConnected = false;

        try {
            //connectedField = urlConnection.getClass().getDeclaredField("connected");
            connectedField = ReflectionHelper.getDeclaredField(urlConnection.getClass(), "connected");
            connectedField.setAccessible(true);
            isConnected = connectedField.getBoolean(urlConnection);
        } catch (Exception ex) {
            System.err.println("Exception message: " + ex.getMessage());
            ex.printStackTrace();
            //System.exit(1);
        }
        return isConnected;
    }

    private KeyStore loadKeystore(String keystorePath, String keystorePassword, String keystoreType) throws IOException {
        KeyStore keystore = null;
        FileInputStream fis = null;
        boolean error = false;

        try {
            keystore = KeyStore.getInstance(keystoreType);
            //keystore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
            fis = new FileInputStream(keystorePath);
            keystore.load(fis, keystorePassword.toCharArray());
        } catch (KeyStoreException kex) {
            System.err.println("KeyStore type is not supported or wrong");
            System.err.println("Exception message: " + kex.getMessage());
            kex.printStackTrace();
            error = true;
        } catch (Exception ex) {
            // TODO: UnrecoverableKeyException ukex
            // System.err.println("KeyStore password wrong");
            System.err.println("Exception message: " + ex.getMessage());
            ex.printStackTrace();
            error = true;
        } finally {
            if (fis != null) {
                fis.close();
            }
        }

        if (error) {
            System.exit(1);
        }

        return keystore;
    }
}
