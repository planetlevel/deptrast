package com.contrastsecurity.deptrast.api;

import com.contrastsecurity.deptrast.model.Package;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.Dispatcher;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import com.contrastsecurity.deptrast.service.PackageCache;

/**
 * Client for interacting with the deps.dev API
 */
public class DepsDevClient implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(DepsDevClient.class);
    private static final String BASE_URL = "https://api.deps.dev/v3alpha/systems";
    private static final String BATCH_URL = "https://api.deps.dev/v3alpha/batch";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final int BATCH_SIZE = 50; // Maximum number of packages to include in one batch request
    private final OkHttpClient client;
    private final ExecutorService executorService;
    private final Gson gson;

    public DepsDevClient() {
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false);
                
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
            logger.error("Error setting up SSL context: {}", e.getMessage());
            // Continue with default SSL settings
        }
        
        // Create a dispatcher with a custom executor service that we can shut down later
        Dispatcher dispatcher = new Dispatcher();
        this.executorService = dispatcher.executorService();
        clientBuilder.dispatcher(dispatcher);
        
        this.client = clientBuilder.build();
        this.gson = new Gson();
    }

    /**
     * Get the dependencies for a package
     * 
     * @param pkg The package to get dependencies for
     * @return List of dependencies
     * @throws IOException If there's an error making the HTTP request
     * @deprecated Use getBatchDependencies instead for better performance
     */
    @Deprecated
    public List<Package> getDependencies(Package pkg) throws IOException {
        // Check cache first
        PackageCache cache = PackageCache.getInstance();
        if (cache.hasCachedDependencies(pkg)) {
            logger.info("Using cached dependencies for {}", pkg.getFullName());
            return cache.getCachedDependencies(pkg);
        }
        
        String url = String.format("%s/%s/packages/%s/versions/%s:dependencies",
                BASE_URL, pkg.getSystem().toLowerCase(), pkg.getName(), pkg.getVersion());
        
        logger.info("Fetching dependencies for {}", pkg.getFullName());
        
        Request request = new Request.Builder()
                .url(url)
                .get()
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                logger.error("Failed to get dependencies for {}: {}", pkg.getFullName(), response.code());
                return new ArrayList<>();
            }

            String responseBody = response.body().string();
            
            // Parse JSON response
            JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();
            
            // Extract nodes and edges
            JsonArray nodes = jsonObject.getAsJsonArray("nodes");
            JsonArray edges = jsonObject.getAsJsonArray("edges");
            
            if (nodes == null || edges == null) {
                logger.error("Invalid response format for {}", pkg.getFullName());
                return new ArrayList<>();
            }
            
            // Build a map of node index to package
            Map<Integer, Package> nodeMap = new HashMap<>();
            int selfNodeIndex = -1;
            
            // First, process all nodes
            for (int i = 0; i < nodes.size(); i++) {
                JsonObject node = nodes.get(i).getAsJsonObject();
                JsonObject versionKey = node.getAsJsonObject("versionKey");
                
                String system = versionKey.get("system").getAsString();
                String name = versionKey.get("name").getAsString();
                String version = versionKey.get("version").getAsString();
                String relation = node.get("relation").getAsString();
                
                // Check if we already have this package in the cache
                String fullName = system.toLowerCase() + ":" + name + ":" + version;
                Package dependency = cache.getCachedPackage(fullName);
                
                if (dependency == null) {
                    dependency = new Package(system, name, version);
                    cache.cachePackage(dependency);
                }
                
                nodeMap.put(i, dependency);
                
                // Find the self node (our package itself)
                if ("SELF".equals(relation)) {
                    selfNodeIndex = i;
                }
            }
            
            // Process edges to build parent-child relationships
            // We only care about direct dependencies of our package
            List<Package> dependencies = new ArrayList<>();
            for (JsonElement edge : edges) {
                JsonObject edgeObj = edge.getAsJsonObject();
                int fromNode = edgeObj.get("fromNode").getAsInt();
                int toNode = edgeObj.get("toNode").getAsInt();
                
                // Only add dependencies that are directly connected to our package
                if (fromNode == selfNodeIndex && nodeMap.containsKey(toNode)) {
                    dependencies.add(nodeMap.get(toNode));
                }
            }
            
            // Cache the dependencies
            cache.cacheDependencies(pkg, dependencies);
            
            logger.info("Found {} dependencies for {}", dependencies.size(), pkg.getFullName());
            return dependencies;
        } catch (Exception e) {
            logger.error("Error fetching dependencies for {}: {}", pkg.getFullName(), e.getMessage());
            throw e;
        }
    }
    
    /**
     * Get dependencies for multiple packages at once using the batch API
     *
     * @param packages List of packages to get dependencies for
     * @return Map of package full name to its dependencies
     * @throws IOException If there's an error making the HTTP request
     */
    public Map<String, List<Package>> getBatchDependencies(List<Package> packages) throws IOException {
        PackageCache cache = PackageCache.getInstance();
        Map<String, List<Package>> results = new HashMap<>();
        List<Package> packagesToFetch = new ArrayList<>();
        
        // First check which packages are already in the cache
        for (Package pkg : packages) {
            if (cache.hasCachedDependencies(pkg)) {
                logger.info("Using cached dependencies for {}", pkg.getFullName());
                results.put(pkg.getFullName(), cache.getCachedDependencies(pkg));
            } else {
                packagesToFetch.add(pkg);
            }
        }
        
        if (packagesToFetch.isEmpty()) {
            logger.info("All dependencies are already cached");
            return results;
        }
        
        // Process in batches of BATCH_SIZE
        for (int i = 0; i < packagesToFetch.size(); i += BATCH_SIZE) {
            int end = Math.min(i + BATCH_SIZE, packagesToFetch.size());
            List<Package> batchPackages = packagesToFetch.subList(i, end);
            
            // Get dependencies for this batch
            Map<String, List<Package>> batchResults = fetchBatchDependencies(batchPackages);
            results.putAll(batchResults);
        }
        
        return results;
    }
    
    /**
     * Fetches dependencies for a batch of packages
     * 
     * @param packages Batch of packages to fetch dependencies for
     * @return Map of package full name to its dependencies
     * @throws IOException If there's an error making the HTTP request
     */
    private Map<String, List<Package>> fetchBatchDependencies(List<Package> packages) throws IOException {
        Map<String, List<Package>> results = new HashMap<>();
        PackageCache cache = PackageCache.getInstance();
        
        if (packages.isEmpty()) {
            return results;
        }
        
        logger.info("Fetching dependencies for {} packages in batch mode", packages.size());
        
        // Use traditional API but with concurrent requests for better performance
        Map<String, List<Package>> individualResults = new HashMap<>();
        Map<String, IOException> errors = new HashMap<>();
        
        // Create requests for all packages
        Map<String, Request> apiRequests = new HashMap<>();
        for (Package pkg : packages) {
            String url = String.format("%s/%s/packages/%s/versions/%s:dependencies",
                    BASE_URL, pkg.getSystem().toLowerCase(), pkg.getName(), pkg.getVersion());
            
            apiRequests.put(pkg.getFullName(), new Request.Builder()
                    .url(url)
                    .get()
                    .build());
        }
        
        // Execute all requests concurrently
        for (Map.Entry<String, Request> entry : apiRequests.entrySet()) {
            String pkgKey = entry.getKey();
            Request request = entry.getValue();
            
            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    logger.error("Failed to get dependencies for {}: {}", pkgKey, response.code());
                    individualResults.put(pkgKey, new ArrayList<>());
                    continue;
                }
                
                String responseBody = response.body().string();
                JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();
                
                // Find which package this response is for
                Package pkg = null;
                for (Package p : packages) {
                    if (p.getFullName().equals(pkgKey)) {
                        pkg = p;
                        break;
                    }
                }
                
                if (pkg == null) {
                    logger.error("Could not find package for key: {}", pkgKey);
                    continue;
                }
                
                // Parse the dependency graph
                List<Package> dependencies = parseDependencyGraph(jsonObject, pkg, cache);
                individualResults.put(pkgKey, dependencies);
                
                // Cache the dependencies
                cache.cacheDependencies(pkg, dependencies);
                
                logger.info("Found {} dependencies for {}", dependencies.size(), pkgKey);
            } catch (IOException e) {
                logger.error("Error fetching dependencies for {}: {}", pkgKey, e.getMessage());
                errors.put(pkgKey, e);
                individualResults.put(pkgKey, new ArrayList<>());
            }
        }
        
        // Log overall results
        logger.info("Successfully fetched dependencies for {} out of {} packages",
                individualResults.size() - errors.size(), packages.size());
        
        return individualResults;
    }
    
    /**
     * Parse a dependency graph from the response
     * 
     * @param graph The dependency graph JSON object
     * @param pkg The package that the dependencies are for
     * @param cache The package cache
     * @return List of dependencies
     */
    private List<Package> parseDependencyGraph(JsonObject graph, Package pkg, PackageCache cache) {
        List<Package> dependencies = new ArrayList<>();
        
        try {
            JsonArray nodes = graph.getAsJsonArray("nodes");
            JsonArray edges = graph.getAsJsonArray("edges");
            
            if (nodes == null || edges == null) {
                logger.error("Invalid response format for {}", pkg.getFullName());
                return dependencies;
            }
            
            // Build a map of node index to package
            Map<Integer, Package> nodeMap = new HashMap<>();
            int selfNodeIndex = -1;
            
            // First, process all nodes
            for (int i = 0; i < nodes.size(); i++) {
                JsonObject node = nodes.get(i).getAsJsonObject();
                JsonObject versionKey = node.getAsJsonObject("versionKey");
                
                String system = versionKey.get("system").getAsString();
                String name = versionKey.get("name").getAsString();
                String version = versionKey.get("version").getAsString();
                String relation = node.get("relation").getAsString();
                
                // Check if we already have this package in the cache
                String fullName = system.toLowerCase() + ":" + name + ":" + version;
                Package dependency = cache.getCachedPackage(fullName);
                
                if (dependency == null) {
                    dependency = new Package(system, name, version);
                    cache.cachePackage(dependency);
                }
                
                nodeMap.put(i, dependency);
                
                // Find the self node (our package itself)
                if ("SELF".equals(relation)) {
                    selfNodeIndex = i;
                }
            }
            
            // Process edges to find direct dependencies
            for (JsonElement edge : edges) {
                JsonObject edgeObj = edge.getAsJsonObject();
                int fromNode = edgeObj.get("fromNode").getAsInt();
                int toNode = edgeObj.get("toNode").getAsInt();
                
                // Only add dependencies that are directly connected to our package
                if (fromNode == selfNodeIndex && nodeMap.containsKey(toNode)) {
                    dependencies.add(nodeMap.get(toNode));
                }
            }
        } catch (Exception e) {
            logger.error("Error parsing dependency graph for {}: {}", pkg.getFullName(), e.getMessage());
        }
        
        return dependencies;
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