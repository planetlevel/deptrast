package com.contrastsecurity.deptrast.api;

import com.contrastsecurity.deptrast.model.Package;
import com.contrastsecurity.deptrast.util.SSLUtils;
import com.contrastsecurity.deptrast.version.VersionParser;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.Dispatcher;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Client for interacting with the deps.dev API
 */
public class DepsDevClient implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(DepsDevClient.class);
    private static final String BASE_URL = "https://api.deps.dev/v3/systems";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private final OkHttpClient client;
    private final ExecutorService executorService;
    private final Gson gson;

    public DepsDevClient() {
        OkHttpClient.Builder clientBuilder = SSLUtils.createHttpClientBuilder()
                .retryOnConnectionFailure(false);

        // Create a dispatcher with a custom executor service that we can shut down later
        Dispatcher dispatcher = new Dispatcher();
        this.executorService = dispatcher.executorService();
        clientBuilder.dispatcher(dispatcher);

        this.client = clientBuilder.build();
        this.gson = new Gson();
    }

    /**
     * Get the raw dependency graph for a package from deps.dev API
     *
     * For vendor-patched versions (like HeroDevs NES), this uses the upstream
     * version for deps.dev queries since deps.dev only knows about the original
     * Maven Central versions.
     *
     * @param pkg The package to get the dependency graph for
     * @return JsonObject containing the full dependency graph (nodes and edges)
     * @throws IOException If there's an error making the HTTP request
     */
    public JsonObject getDependencyGraph(Package pkg) throws IOException {
        // Parse version to handle vendor-specific formats (e.g., HeroDevs)
        String depsDevVersion = VersionParser.getDepsDevVersion(pkg.getVersion());

        String url = String.format("%s/%s/packages/%s/versions/%s:dependencies",
                BASE_URL, pkg.getSystem().toLowerCase(), pkg.getName(), depsDevVersion);

        logger.debug("Fetching dependency graph for {}", pkg.getFullName());
        if (!depsDevVersion.equals(pkg.getVersion())) {
            logger.debug("  Original version: {}", pkg.getVersion());
            logger.debug("  deps.dev version: {}", depsDevVersion);
        }

        Request request = new Request.Builder()
                .url(url)
                .get()
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                logger.info("Failed to get dependency graph for {}: {}", pkg.getFullName(), response.code());
                return null;
            }

            String responseBody = response.body().string();
            return JsonParser.parseString(responseBody).getAsJsonObject();
        }
    }

    /**
     * Closes the client and releases resources
     */
    @Override
    public void close() {
        // Cancel all ongoing requests first
        client.dispatcher().cancelAll();

        // Close connection pool
        client.connectionPool().evictAll();

        // Shutdown dispatcher's executor service
        client.dispatcher().executorService().shutdown();

        try {
            // Wait longer for thread termination (15 seconds to match Maven's timeout)
            if (!executorService.awaitTermination(15, TimeUnit.SECONDS)) {
                // Try forcing shutdown
                executorService.shutdownNow();
                // Wait again
                if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                    logger.warn("Failed to terminate OkHttp threads cleanly");
                }
            }
        } catch (InterruptedException e) {
            logger.warn("Thread shutdown interrupted", e);
            executorService.shutdownNow();
            Thread.currentThread().interrupt(); // Preserve interrupt status
        }
    }
}
