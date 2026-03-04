
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.StructuredTaskScope;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.google.cloud.ServiceOptions;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageException;
import com.google.cloud.storage.StorageOptions;

import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.spi.JsonProvider;

public class WitnessAgent implements HttpFunction {

    private static final Logger LOG = Logger.getLogger(WitnessAgent.class.getName());

    // Explicitly using Virtual Threads to handle parallel I/O pipelines
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    private final HttpClient CLIENT = HttpClient.newBuilder()
            .executor(Executors.newVirtualThreadPerTaskExecutor())
            .build();

    // Static initialization
    private static final JsonProvider JSON = JsonProvider.provider();
    private static final Storage STORAGE = StorageOptions.getDefaultInstance().getService();

    // Environment variables
    private static final String BUCKET_NAME;

    // Static configuration detected at startup
    private static final String PROJECT;

    static {
        var kmsLocation = System.getenv("KMS_LOCATION");
        var kmsKeyRingName = System.getenv("KMS_KEY_RING");

        BUCKET_NAME = System.getenv("BUCKET_NAME");

        if (kmsLocation == null || kmsKeyRingName == null || BUCKET_NAME == null) {
            throw new IllegalStateException("Incomplete environment configuration");
        }

        PROJECT = ServiceOptions.getDefaultProjectId();

            // TODO check IAM rights

//            LOG.info(String.format("Initialized for %s at %s.",
//                    kmsKeyRingName,
//                    kmsLocation));

//        } catch (IOException e) {
//            throw new IllegalStateException("KMS initialization failed", e);
//        }
    }

    @Override
    public void service(HttpRequest request, HttpResponse response) throws Exception {

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            sendError(response, 405, "Method Not Allowed", "Use POST");
            return;
        }

        JsonObject payload = null;

        try (final var parser = JSON.createReader(request.getInputStream())) {

            payload = parser.readObject();

        } catch (JsonException e) {
            sendError(response, 400, "Bad Request", e.getMessage());
            return;

        } catch (Exception e) {
            sendError(response, 400, "Bad Request", "Malformatted body");
            return;
        }

        var did = "did:cel:zW1jvitG8gnmFE4KRt7KeWp2DrdB7sCLXjh1tJtigd5tSRt";
        List<String> witnesses = List.of("dsad");

        final var methodSpecificId = did.substring("did:cel:".length());

        try {
            // The event log location
            final var blobId = BlobId.of(BUCKET_NAME, methodSpecificId);

//            CompletableFuture<?>[] pipelines = witnesses.stream()
//                    .<CompletableFuture<Void>>map(url -> CompletableFuture.runAsync(() -> {
//                        try {
//                            processWitnessPipeline(blobId, url);
//                        } catch (Exception e) {
//                            // Pipeline-specific failure handling
//                        }
//                    }, executor))
//                    .toArray(CompletableFuture[]::new);

            // Execute 1-5 independent pipelines in parallel
            var requests = witnesses.stream()
                    .map(url -> CompletableFuture.runAsync(() -> processWitnessPipeline(blobId, url), executor))
                    .toArray(CompletableFuture[]::new);

            // Wait for all requests to resolve (success or failure)
            CompletableFuture.allOf(requests).join();

            response.setStatusCode(200);
            response.setContentType("application/json");

            try (final var writer = JSON.createGenerator(response.getOutputStream())) {
                writer.write("TODO");
            }

        } catch (IllegalArgumentException e) {
            sendError(response, 400, "Bad Request", e.getMessage());

        } catch (Exception e) {
            LOG.severe(e.getMessage());
            sendError(response, 500, "Internal Service Error", e.getMessage());
        }
    }

    private void processWitnessPipeline(BlobId blobId, String url) {

    }

    private static void sendError(HttpResponse response, int code, String status, String message) throws IOException {
        response.setStatusCode(code, status);
        response.setContentType("application/json");

        try (final var gen = JSON.createGenerator(response.getWriter())) {
            gen.writeStartObject()
                    .write("status", status)
                    .write("message", message)
                    .writeEnd();
        }
    }

    private void storeLog(String id, byte[] content) {
        // Minimal write: storage.create() only requires roles/storage.objectCreator
        STORAGE.create(BlobInfo.newBuilder(BlobId.of(BUCKET_NAME, id))
                .setContentType("application/json")
                .build(), content);
    }

//    private String callWitness(String url, String hash) throws Exception {
//        var req = java.net.http.HttpRequest.newBuilder(URI.create(url))
//                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(hash))
//                .timeout(java.time.Duration.ofSeconds(5))
//                .build();
//
//        var resp = CLIENT.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
//        if (resp.statusCode() != 200)
//            throw new RuntimeException("Witness failed: " + url);
//        return resp.body();
//    }

//    private String executeWitnessCalls(String hashHex) throws Exception {
//        List<String> urls = List.of(System.getenv("WITNESS_URLS").split(","));
//        try (var scope = new StructuredTaskScope.ShutdownOnFailure()) {
//            List<StructuredTaskScope.Subtask<String>> tasks = urls.stream()
//                    .map(url -> scope.fork(() -> {
//                        var req = HttpRequest.newBuilder(URI.create(url))
//                                .POST(HttpRequest.BodyPublishers.ofString(hashHex))
//                                .build();
//                        return httpClient.send(req, HttpResponse.BodyHandlers.ofString()).body();
//                    })).toList();
//            scope.join().throwIfFailed();
//            return tasks.stream().map(StructuredTaskScope.Subtask::get).collect(Collectors.joining("\n"));
//        }
//    }
//
//    private void attemptAtomicCommit(Blob logBlob, String bundle) {
//        int maxRetries = 5;
//        Blob currentBase = logBlob;
//
//        for (int i = 0; i < maxRetries; i++) {
//            // We still need a source for the witness data to use GCS Compose
//            String sidecarName = currentBase.getName() + ".witness";
//            Blob sidecar = storage.create(BlobInfo.newBuilder(bucketName, sidecarName).build(), bundle.getBytes());
//
//            try {
//                Storage.ComposeRequest comp = Storage.ComposeRequest.newBuilder()
//                        .addSource(currentBase.getName())
//                        .addSource(sidecarName)
//                        .setTarget(BlobInfo.newBuilder(bucketName, currentBase.getName()).build())
//                        .setTargetOptions(Storage.BlobTargetOption.generationMatch(currentBase.getGeneration()))
//                        .build();
//
//                storage.compose(comp);
//                storage.delete(sidecar.getBlobId());
//                return; // Success
//            } catch (StorageException e) {
//                storage.delete(sidecar.getBlobId());
//                if (e.getCode() == 412) {
//                    // Only fetch the metadata to get the new generation, don't download content
//                    currentBase = storage.get(currentBase.getBlobId(),
//                            Storage.BlobGetOption.fields(Storage.BlobField.GENERATION));
//                } else {
//                    throw e; // Fail on any other error
//                }
//            }
//        }
//        throw new RuntimeException("Failed to commit after retries due to high contention");
//    }

}
