package com.apicatalog.cel.resolver;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;

import com.apicatalog.cel.CelException;
import com.apicatalog.cel.CelException.ErrorCode;
import com.apicatalog.cel.EventLog;

import jakarta.json.Json;

public class CelResolver {

    private EventLogLoader loader;

    public CelResolver(EventLogLoader loader) {
        this.loader = loader;
    }

    public Map<String, Object> resolve(String identifier, Collection<String> endpoints) throws CelException {

        Objects.requireNonNull(identifier);
        Objects.requireNonNull(endpoints);

        // If the identifier does not start with the did:cel: prefix, an UNSUPPORTED_ID
        // error MUST be raised and processing MUST be aborted.
        if (!identifier.startsWith("did:cel:")) {
            throw new IllegalArgumentException();
        }

        // Extract did as the substring of identifier corresponding to the DID,
        // excluding any path, query, or fragment components of the DID URL.
        String did = identifier; // FIXME final

        // Locate and retrieve the cryptographic event logs
        final CompletableFuture<Map.Entry<String, EventLog>>[] logMapEntryFutures;
        int index = 0;

        // If the identifier is a DID URL containing a storage parameter and
        // options.followStorage is true, add the storage parameter value to the
        // endpoints.
        int storageIndex = identifier.indexOf("?storage=");
        if (storageIndex != -1) {
            did = identifier.substring(0, storageIndex); // TODO remove
            final var storage = identifier.substring(storageIndex + "?storage=".length());

            logMapEntryFutures = new CompletableFuture[endpoints.size() + 1];
            logMapEntryFutures[index++] = loader.load(did, storage)
                    .thenApply(log -> Map.entry(storage, log));

        } else {

            if (endpoints.isEmpty()) {
                throw new IllegalArgumentException();
            }

            logMapEntryFutures = new CompletableFuture[endpoints.size()];
        }

        // For each endpoint in endpoints perform in parallel
        for (var endpoint : endpoints) {
            logMapEntryFutures[index++] = loader.load(did, endpoint)
                    .thenApply(log -> log != null ? Map.entry(endpoint, log) : null);
        }

        // Wait for all requests to resolve (success or failure)
        CompletableFuture.allOf(logMapEntryFutures).join();

        // Collect fetched event logs
        var logMapEntries = new ArrayList<Map.Entry<String, EventLog>>(logMapEntryFutures.length);

        // Add a new entry to logMap with key endpoint and value log.
        for (var logMapEntryFuture : logMapEntryFutures) {
            try {
                var logMapEntry = (Map.Entry<String, EventLog>) logMapEntryFuture.get();
                if (logMapEntry != null) {
                    logMapEntries.add(logMapEntry);
                }
                // TODO log errors
            } catch (InterruptedException | ExecutionException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        // If logMap is empty, a LOG_NOT_FOUND error MUST be raised and processing MUST
        // be aborted.
        if (logMapEntries.isEmpty()) {
            throw new IllegalArgumentException();
        }

        // Sort the logMap in descending order by the number of events contained in each
        // log. An implementation MAY define additional sort criteria.
        Collections.sort(logMapEntries, (a, b) -> a.getValue().length() - b.getValue().length());

        // Iterate over logMap entries. Let log be the entry value and endpoint the
        // entry key.
        for (var logEntry : logMapEntries) {
            IO.println("logEntry: " + logEntry);

            try {
                return logEntry.getValue().verify(did);
                
            } catch (IllegalArgumentException e) {
                // ignore errors and continue with the next logMap entry
                e.printStackTrace();
            }
        }

        // Resolution failed, a RESOLUTION_FAILED error MUST be raised.
        throw new CelException(ErrorCode.RESOLUTION_FAILED);
    }

    public static void main(String[] args) throws CelException {

        var JSON_PARSER = Json.createParserFactory(Map.of());

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {

            try (var client = HttpClient.newBuilder().executor(executor).build()) {

                new CelResolver((did, endpoint) -> {

                    var uri = endpoint + did.substring("did:cel:".length());

                    return client.sendAsync(
                            HttpRequest.newBuilder(URI.create(uri)).GET().build(),
                            HttpResponse.BodyHandlers.ofInputStream())
                            .thenApply(response -> {

                                if (response.statusCode() == 200) {
                                    try (var parser = JSON_PARSER.createParser(response.body())) {
                                        return EventLog.read(parser);
                                    }
                                }

                                IO.println("TODO ERROR " + uri + " -> " + response.statusCode());

                                return null;
                            });

                }).resolve(
                        "did:cel:zW1aUdGpZoVs789MPqMuHhgnpyk7yzrfMUs3p7VGk7vqTmi?storage=https://storage.googleapis.com/did-cel-log/",
                        List.of()
//                        List.of("https://raw.githubusercontent.com/apicatalog/did-cel-log1/refs/heads/main/")

                );
            }
        }
    }

}
