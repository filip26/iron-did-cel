package com.apicatalog.cel.resolver;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;

import com.apicatalog.cel.CelData;
import com.apicatalog.cel.CelException;
import com.apicatalog.cel.CelException.ErrorCode;
import com.apicatalog.cel.Event;
import com.apicatalog.cel.EventEntry;
import com.apicatalog.cel.EventEntryVerifier;
import com.apicatalog.cel.EventLog;
import com.apicatalog.cel.EventVerifier;
import com.apicatalog.cel.io.JakartaEventLogReader;
import com.apicatalog.cel.loader.EventLogLoader;
import com.apicatalog.cel.loader.HttpLoader;
import com.apicatalog.cel.status.EventStatus;
import com.apicatalog.cel.status.LruEventStatusCache;

public class CelResolver {

    private EventLogLoader loader;
    private EventStatus eventStatus;
    private EventVerifier eventVerifier;
    private EventEntryVerifier eventEntryVerifier;

    public CelResolver(
            EventLogLoader loader,
            EventStatus cache,
            EventVerifier verifier,
            EventEntryVerifier eventEntryVerifier) {
        this.loader = loader;
        this.eventStatus = cache;
        this.eventVerifier = verifier;
        this.eventEntryVerifier = eventEntryVerifier;
    }

    // <location, log>>
    public Map.Entry<String, EventLog> resolve(
            final String identifier,
            final Collection<String> endpoints,
            final boolean followStorage) throws CelException {

        Objects.requireNonNull(identifier);
        Objects.requireNonNull(endpoints);

        // If the identifier does not start with the did:cel: prefix, an UNSUPPORTED_ID
        // error MUST be raised and processing MUST be aborted.
        if (!identifier.startsWith("did:cel:")) {
            throw new CelException(ErrorCode.UNSUPPORTED_ID, "The identifier " + identifier + " is not supported");
        }

        // Extract did as the substring of identifier corresponding to the DID,
        // excluding any path, query, or fragment components of the DID URL.
        String did = identifier; // FIXME final

        // Locate and retrieve the cryptographic event logs
        final var logMapEntryFutures = new ArrayList<CompletableFuture<Map.Entry<String, EventLog>>>(
                endpoints.size() + 1);

        // If the identifier is a DID URL containing a storage parameter and
        // options.followStorage is true, add the storage parameter value to the
        // endpoints.
        if (followStorage) {
            int storageIndex = identifier.indexOf("?storage=");
            if (storageIndex != -1) {
                did = identifier.substring(0, storageIndex); // TODO remove

                var storage = identifier.substring(storageIndex + "?storage=".length());

                if (!endpoints.contains(storage)) {
                    logMapEntryFutures.add(loader.load(did, storage)
                            .thenApply(log -> Map.entry(storage, log)));
                }
            }
        }

        if (logMapEntryFutures.isEmpty() && endpoints.isEmpty()) {
            throw new CelException(ErrorCode.NO_SERVICE_ENDPOINTS);
        }

        // For each endpoint in endpoints perform in parallel
        for (var endpoint : endpoints) {
            try {
                logMapEntryFutures.add(loader.load(endpoint, did)
                        .thenApply(log -> log != null ? Map.entry(endpoint, log) : null));
            } catch (IllegalArgumentException e) {
                // Ignore loader initialization failures
            }
        }
        
        if (logMapEntryFutures.isEmpty()) {
            throw new CelException(ErrorCode.INVALID_SERVICE_ENDPOINTS);
        }

        // Wait for all requests to resolve (success or failure)
        try {
            CompletableFuture.allOf(logMapEntryFutures.toArray(CompletableFuture[]::new)).join();
        } catch (CompletionException | CancellationException e) {
            // Ignore failed futures
        }

        // Collect fetched event logs
        var logMapEntries = new ArrayList<Map.Entry<String, EventLog>>(logMapEntryFutures.size());

        // Add a new entry to logMap with key endpoint and value log.
        try {
            for (var logMapEntryFuture : logMapEntryFutures) {
                if (logMapEntryFuture.isDone() && !logMapEntryFuture.isCompletedExceptionally()) {
                    var logMapEntry = (Map.Entry<String, EventLog>) logMapEntryFuture.get();
                    if (logMapEntry != null) {
                        logMapEntries.add(logMapEntry);
                    }
                }
            }
        } catch (InterruptedException | ExecutionException e) {
            // Should not happen here
            throw new IllegalStateException(e);
        }

        // If logMap is empty, a LOG_NOT_FOUND error MUST be raised and processing MUST
        // be aborted.
        if (logMapEntries.isEmpty()) {
            throw new CelException(ErrorCode.LOG_NOT_FOUND);
        }

        // Sort the logMap in descending order by the number of events contained in each
        // log. An implementation MAY define additional sort criteria.
        Collections.sort(logMapEntries, (a, b) -> a.getValue().length() - b.getValue().length());

        // Iterate over logMap entries. Let log be the entry value and endpoint the
        // entry key.
        for (var logMapEntry : logMapEntries) {

            try {

                var log = logMapEntry.getValue();

                log.verify(did, eventStatus, eventVerifier, eventEntryVerifier);

                return Map.entry(
                        logMapEntry.getKey(),
                        log);

            } catch (IllegalArgumentException | IllegalStateException e) {
                // Ignore errors and continue with the next logMap entry
                e.printStackTrace();
            } catch (CelException e) {
                if (ErrorCode.DEACTIVATED == e.getCode()) {
                    throw e;
                }
                // Ignore other errors and continue with the next logMap entry
                e.printStackTrace();
            }
        }

        // Resolution failed, a RESOLUTION_FAILED error MUST be raised.
        throw new CelException(ErrorCode.RESOLUTION_FAILED);
    }

    public static void main(String[] args) throws CelException {
;
        var eventLogReader = new JakartaEventLogReader();

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {

            try (var httpClient = HttpClient.newBuilder().executor(executor).build()) {

                var result = new CelResolver(
                        new HttpLoader(eventLogReader, httpClient),
                        new LruEventStatusCache(1000),
                        new EventVerifier() {

                            @Override
                            public void verify(Event event, CelData data) {

                                // TODO Auto-generated method stub

                            }
                        },
                        new EventEntryVerifier() {

                            @Override
                            public void verify(EventEntry event) {
                                // TODO Auto-generated method stub

                            }
                        }).resolve(
                                "did:cel:zW1aUdGpZoVs789MPqMuHhgnpyk7yzrfMUs3p7VGk7vqTmi",
//                        List.of()
                                List.of("https://storage.googleapis.com/did-cel-log/",
                                        "https://raw.githubusercontent.com/apicatalog/did-cel-log/refs/heads/main/")
//                        List.of("https://raw.githubusercontent.com/apicatalog/did-cel-log1/refs/heads/main/")
                                , true);

                IO.println(result);
            }
        }
    }

}
