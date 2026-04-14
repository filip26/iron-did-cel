package com.apicatalog.cel.loader;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import com.apicatalog.cel.EventLog;
import com.apicatalog.cel.resolver.CelResolver;

import jakarta.json.Json;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParserFactory;

public class HttpLoader implements EventLogLoader {

    private final JsonParserFactory jsonParserFactory;
    private final HttpClient client;

    public HttpLoader(JsonParserFactory jsonParserFactory, HttpClient httpClient) {
        this.jsonParserFactory = jsonParserFactory;
        this.client = httpClient;
    }

    @Override
    public CompletableFuture<EventLog> load(String did, String endpoint) {

        var uri = endpoint + did.substring("did:cel:".length());

        return client.sendAsync(
                HttpRequest.newBuilder(URI.create(uri)).GET().build(),
                HttpResponse.BodyHandlers.ofInputStream())
                .thenApply(response -> {
                    if (response.statusCode() == 200) {
                        try (var parser = jsonParserFactory.createParser(response.body())) {
                            return EventLog.read(parser);
                        }
                    }
                    throw new IllegalArgumentException(); // TODO message
                });
    }

}
