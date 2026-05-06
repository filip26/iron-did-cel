package com.apicatalog.cel.loader;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletableFuture;

import com.apicatalog.cel.EventLog;
import com.apicatalog.cel.io.EventLogReader;

public class HttpLoader implements EventLogLoader {

    private final EventLogReader eventLogReader;
    private final HttpClient client;

    public HttpLoader(EventLogReader eventLogReader, HttpClient httpClient) {
        this.eventLogReader = eventLogReader;
        this.client = httpClient;
    }

    @Override
    public CompletableFuture<EventLog> load(String endpoint, String did) {

        var uri = endpoint + did.substring("did:cel:".length());

        return client.sendAsync(
                HttpRequest.newBuilder(URI.create(uri)).GET().build(),
                HttpResponse.BodyHandlers.ofInputStream())
                .thenApply(response -> {
                    if (response.statusCode() == 200) {
                        return eventLogReader.read(
                                response.headers()
                                        .firstValue("content-type")
                                        .orElse(null),
                                response.body());
                    }
                    throw new IllegalArgumentException(); // TODO message
                });
    }

}
