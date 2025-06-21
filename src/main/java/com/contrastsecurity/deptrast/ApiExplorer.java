package com.contrastsecurity.deptrast;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

/**
 * Simple diagnostic tool to explore the deps.dev API
 */
public class ApiExplorer {
    
    public static void main(String[] args) {
        OkHttpClient client = createHttpClient();
        
        // Testing v3alpha endpoints for dependencies with npm
        testEndpoint(client, "https://api.deps.dev/v3alpha/systems/npm/packages/lodash/versions/4.17.21:dependencies");
        
        // Testing v3alpha endpoints for dependencies with Maven
        testEndpoint(client, "https://api.deps.dev/v3alpha/systems/maven/packages/org.springframework.boot:spring-boot-starter-web/versions/3.1.0:dependencies");
        
        // Test with another Maven package
        testEndpoint(client, "https://api.deps.dev/v3alpha/systems/maven/packages/com.google.guava:guava/versions/31.1-jre:dependencies");
    }
    
    private static OkHttpClient createHttpClient() {
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS);
                
        // Create a trust manager that does not validate certificate chains
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }
    
                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }
    
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };
    
            // Install the all-trusting trust manager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            
            // Create an SSL socket factory with our all-trusting manager
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            
            // Set SSL settings on the client builder
            clientBuilder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0])
                         .hostnameVerifier((hostname, session) -> true);
                    
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            System.err.println("Error setting up SSL context: " + e.getMessage());
            // Continue with default SSL settings
        }
        
        return clientBuilder.build();
    }
    
    private static void testEndpoint(OkHttpClient client, String url) {
        System.out.println("\nTesting endpoint: " + url);
        
        Request request = new Request.Builder()
                .url(url)
                .get()
                .build();

        try (Response response = client.newCall(request).execute()) {
            System.out.println("Response code: " + response.code());
            if (response.isSuccessful()) {
                String responseBody = response.body().string();
                System.out.println("Response body (full): " + responseBody);
            }
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}