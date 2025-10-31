package com.contrastsecurity.deptrast.util;

import okhttp3.OkHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

/**
 * Utility class for creating OkHttpClient instances with SSL configuration.
 *
 * WARNING: This class disables SSL certificate validation to support environments
 * with SSL-intercepting proxies. See README.md for security implications.
 */
public class SSLUtils {
    private static final Logger logger = LoggerFactory.getLogger(SSLUtils.class);

    private SSLUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Creates an OkHttpClient.Builder with default timeouts and SSL configuration.
     *
     * WARNING: SSL certificate validation is DISABLED. This makes the connection
     * vulnerable to man-in-the-middle attacks. Use only on trusted networks.
     *
     * @return Configured OkHttpClient.Builder
     */
    public static OkHttpClient.Builder createHttpClientBuilder() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true);

        configureTrustAllSSL(builder);
        return builder;
    }

    /**
     * Configures the OkHttpClient.Builder to trust all SSL certificates.
     * This disables certificate validation to support SSL-intercepting proxies.
     *
     * @param builder The OkHttpClient.Builder to configure
     */
    private static void configureTrustAllSSL(OkHttpClient.Builder builder) {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        // Trust all certificates
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        // Trust all certificates
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
                   .hostnameVerifier((hostname, session) -> true);

            logger.warn("SSL certificate validation is DISABLED. Use only on trusted networks.");
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            logger.error("Error configuring SSL context: {}", e.getMessage());
        }
    }
}
