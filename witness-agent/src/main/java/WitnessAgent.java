
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;

import jakarta.json.Json;
import jakarta.json.stream.JsonGeneratorFactory;
import jakarta.json.stream.JsonParserFactory;

public class WitnessAgent implements HttpFunction {

    private static final Logger LOG = Logger.getLogger(WitnessAgent.class.getName());

    // Explicitly using Virtual Threads to handle parallel I/O pipelines
    private final static ExecutorService EXECUTOR = Executors.newVirtualThreadPerTaskExecutor();

    private final static HttpClient CLIENT = HttpClient.newBuilder()
            .executor(EXECUTOR)
            .build();

    // Static initialization
    private static final JsonParserFactory JSON_PARSER = Json.createParserFactory(Map.of());
    private static final JsonGeneratorFactory JSON_GENERATOR = Json.createGeneratorFactory(Map.of());

    private static final Storage STORAGE = StorageOptions.getDefaultInstance().getService();

    // Environment variables
    private static final String BUCKET_NAME;

    static {
        BUCKET_NAME = System.getenv("BUCKET_NAME");

        if (BUCKET_NAME == null) {
            throw new IllegalStateException("Incomplete environment configuration");
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (EXECUTOR != null) {
                EXECUTOR.close();
            }
        }));

        // GCS Check: Verify read (get) and write/update (create) permissions
        var gcsPerms = STORAGE.testIamPermissions(BUCKET_NAME,
                List.of("storage.objects.get", "storage.objects.create"));
        if (gcsPerms.size() < 2) {
            throw new IllegalStateException("Missing GCS permissions in bucket " + BUCKET_NAME + ": " + gcsPerms);
        }

        LOG.info(String.format("Initialized for %s.", BUCKET_NAME));
    }

    @Override
    public void service(HttpRequest request, HttpResponse response) throws Exception {

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            sendError(response, 405, "Method Not Allowed", "Use POST");
            return;
        }

        final WitnessAgentRequest witnessRequest;

        // Parse witness agent request
        try (final var parser = JSON_PARSER.createParser(request.getInputStream())) {
            witnessRequest = WitnessAgentRequest.parse(parser);

        } catch (Exception e) {
            sendError(response, 400, "Bad Request", e.getMessage());
            return;
        }

        final var methodSpecificId = witnessRequest.did().substring("did:cel:".length());

        try {

            // Get the event log
            var blob = STORAGE.get(BlobId.of(
                    BUCKET_NAME, methodSpecificId));

            if (blob == null) {
                sendError(response, 400, "Bad Request",
                        "The event log %s is not found".formatted(witnessRequest.did()));
                return;
            }

            final EventLog eventLog;

            // Parse the fetched event log
            try (final var parser = JSON_PARSER.createParser(new ByteArrayInputStream(blob.getContent()))) {
                eventLog = EventLog.read(parser);

            } catch (Exception e) {
                sendError(response, 400, "Bad Request", e.getMessage());
                return;
            }

            if (eventLog.size() == 0) {
                sendError(response, 400, "Bad Request", "The event log is empty, nothing to witness");
                return;
            }

            // Get multibase encoded digest for the last event in the log to witness
            final var digestMultibase = eventLog.lastEventEntry().digestToWitness();

            // Execute independent witness requests in parallel
            final var witnessEndpoints = witnessRequest.witnessEndpoints().stream()
                    .map(url -> CompletableFuture.supplyAsync(
                            () -> sendWitnessRequest(url, digestMultibase),
                            EXECUTOR))
                    .toList();

            // Wait for all requests to resolve (success or failure)
            CompletableFuture.allOf(witnessEndpoints.toArray(CompletableFuture[]::new)).join();

            // Collect proofs/errors
            var witnessResponses = witnessEndpoints.stream()
                    .map(CompletableFuture::join);

            // Get only proofs
            var witnessProofs = witnessResponses
                    .filter(m -> !"Error".equals(m.get("type")))
                    .toList();

            // Assembly event log update of new witness proofs attached to the last event
            eventLog.lastEventEntry().addProof(witnessProofs);

            // Store update event log
            storeLog(methodSpecificId, blob, eventLog.toByteArray(JSON_GENERATOR));

            // Send response headers
            response.setStatusCode(200);
            response.setContentType("application/json");

            // Write witness services response as the response body
            try (final var gen = JSON_GENERATOR.createGenerator(response.getWriter())) {
                gen.writeStartArray();
                witnessResponses.forEach(witnessResponse -> {
                    gen.writeStartObject();
                    for (var entry : witnessResponse.entrySet()) {
                        gen.write(entry.getKey(), entry.getValue());
                    }
                    gen.writeEnd();
                });
                gen.writeEnd();
            }

        } catch (Exception e) {
            LOG.severe(e.getMessage());
            sendError(response, 500, "Internal Server Error", e.getMessage());
        }
    }

    private Map<String, String> sendWitnessRequest(String uri, String digestMultibase) {

        var req = java.net.http.HttpRequest.newBuilder(URI.create(uri))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                        "{\"digestMultibase\": \"" + digestMultibase + "\"}"))
                .build();

        try {
            var res = CLIENT.send(req, BodyHandlers.ofInputStream());

            if (res.statusCode() == 200) {
                try (var parser = JSON_PARSER.createParser(res.body())) {
                    return WitnessServiceResponse.parse(parser);
                }
            }

            return Map.of(
                    "type", "Error",
                    "message", "Expected 200 OK status code, but got " + res.statusCode(),
                    "uri", uri);

        } catch (Exception e) {
            return Map.of(
                    "type", "Error",
                    "message", e.getMessage(),
                    "uri", uri);
        }
    }

    private void storeLog(String id, Blob blob, byte[] log) {
        // Minimal write: storage.create() only requires roles/storage.objectCreator
//        STORAGE.createFrom(blob, null, null);
        STORAGE.create(BlobInfo.newBuilder(BlobId.of(BUCKET_NAME, id))
                .setContentType("application/json")
                .build(), log, Storage.BlobTargetOption.generationMatch(blob.getGeneration()));
    }

    private static void sendError(HttpResponse response, int code, String status, String message) throws IOException {
        response.setStatusCode(code, status);
        response.setContentType("application/json");

        try (final var gen = JSON_GENERATOR.createGenerator(response.getWriter())) {
            gen.writeStartObject()
                    .write("type", "Error")
                    .write("status", status)
                    .write("message", message)
                    .writeEnd();
        }
    }
}
