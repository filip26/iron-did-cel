
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

import com.apicatalog.jcs.Jcs;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.codec.MultihashCodec;
import com.apicatalog.tree.io.jakarta.JakartaAdapter;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import jakarta.json.JsonValue.ValueType;
import jakarta.json.spi.JsonProvider;
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
    @Deprecated
    private static final JsonProvider JSON = JsonProvider.provider();
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

        try (final var parser = JSON_PARSER.createParser(request.getInputStream())) {
            
            witnessRequest = WitnessAgentRequest.parse(parser);

        } catch (Exception e) {
            sendError(response, 400, "Bad Request", e.getMessage());
            return;
        }

        final var methodSpecificId = witnessRequest.did().substring("did:cel:".length());

        try {
            // The event log location
            final var blobId = BlobId.of(BUCKET_NAME, methodSpecificId);

            // Get the event log
            Blob blob = STORAGE.get(blobId);

            if (blob == null) {
                sendError(response, 404, "Not Found", witnessRequest.did() + " is not found");
                return;
            }

            final JsonObject jsonLog;
            final JsonArray jsonEvents;
            final JsonObject jsonEvent;

            try (final var parser = JSON.createReader(new ByteArrayInputStream(blob.getContent()))) {

                jsonLog = parser.readObject();
                jsonEvents = jsonLog.getJsonArray("log");

                // witness the last log event - TODO configurable per request
                jsonEvent = jsonEvents.getJsonObject(jsonEvents.size() - 1);
            }

            // extract existing proofs
            var existingProofs = jsonEvent.get("proof");

            // remove proofs
            var unsignedEvent = existingProofs != null
                    ? JSON.createObjectBuilder(jsonEvent).remove("proof").build()
                    : jsonEvent;

            var c14Event = Jcs.canonize(unsignedEvent, JakartaAdapter.instance());

            final var digestMultibase = Multibase.BASE_58_BTC.encode(
                    MultihashCodec.SHA3_256.encode(
                            MessageDigest.getInstance("SHA3-256").digest(
                                    c14Event.getBytes(StandardCharsets.UTF_8))));

            // Execute independent witness requests in parallel
            final var witnessEndpoints = witnessRequest.witnessEndpoints().stream()
                    .map(url -> CompletableFuture.supplyAsync(
                            () -> sendWitnessRequest(url, digestMultibase),
                            EXECUTOR))
                    .toList();

            // Wait for all requests to resolve (success or failure)
            CompletableFuture.allOf(witnessEndpoints.toArray(CompletableFuture[]::new)).join();

            // Collect proofs/errors
            var witnessProofs = witnessEndpoints.stream()
                    .map(CompletableFuture::join)
                    .toList();

            // assembly witnessed event
            var witnessedBuilder = JSON.createObjectBuilder(unsignedEvent);
            var proofs = mergeProofs(existingProofs, witnessProofs);

            var witnessed = witnessedBuilder.add("proof", proofs).build();

            var updatedLog = JSON.createObjectBuilder(jsonLog);

            updatedLog.add("log", JSON.createArrayBuilder(jsonEvents)
                    .remove(jsonEvents.size() - 1)
                    .add(witnessed));

            storeLog(methodSpecificId, blob, updatedLog.build().toString().getBytes(StandardCharsets.UTF_8));

            // send response
            response.setStatusCode(200);
            response.setContentType("application/json");

            try (final var writer = response.getWriter()) {
                writer.write(witnessed.toString());
            }

        } catch (Exception e) {
            LOG.severe(e.getMessage());
            sendError(response, 500, "Internal Service Error", e.getMessage());
        }
    }

    private JsonArray mergeProofs(JsonValue existingProofs, List<JsonObject> witnessProofs) {

        var proofs = JSON.createArrayBuilder();

        if (existingProofs != null && ValueType.NULL != existingProofs.getValueType()) {
            if (existingProofs instanceof JsonArray array) {
                array.stream().forEach(proofs::add);
            } else {
                proofs.add(existingProofs);
            }
        }

        for (var proof : witnessProofs) {
            proofs.add(proof);
        }

        return proofs.build();
    }

    private JsonObject sendWitnessRequest(String url, String digestMultibase) {

        var req = java.net.http.HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                        "{\"digestMultibase\": \"" + digestMultibase + "\"}"))
                .build();

        try {
            var res = CLIENT.send(req, BodyHandlers.ofInputStream());

            if (res.statusCode() == 200) {
                try (var reader = JSON.createReader(res.body())) {
                    return reader.readObject();
                }
            }

        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // TODO
        return null;
    }

    private void storeLog(String id, Blob blob, byte[] log) {
        // Minimal write: storage.create() only requires roles/storage.objectCreator
        STORAGE.create(BlobInfo.newBuilder(BlobId.of(BUCKET_NAME, id))
                .setContentType("application/json")
                .build(), log, Storage.BlobTargetOption.generationMatch(blob.getGeneration()));
    }

    private static void sendError(HttpResponse response, int code, String status, String message) throws IOException {
        response.setStatusCode(code, status);
        response.setContentType("application/json");

        try (final var gen = JSON_GENERATOR.createGenerator(response.getWriter())) {
            gen.writeStartObject()
                    .write("status", status)
                    .write("message", message)
                    .writeEnd();
        }
    }
}
