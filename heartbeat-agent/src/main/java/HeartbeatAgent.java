import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutures;
import com.google.api.core.SettableApiFuture;
import com.google.cloud.ServiceOptions;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.cloud.tasks.v2.CloudTasksClient;
import com.google.cloud.tasks.v2.CreateTaskRequest;
import com.google.cloud.tasks.v2.HttpMethod;
import com.google.cloud.tasks.v2.QueueName;
import com.google.cloud.tasks.v2.Task;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.protobuf.ByteString;

import jakarta.json.Json;
import jakarta.json.stream.JsonGeneratorFactory;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParser.Event;
import jakarta.json.stream.JsonParserFactory;

public class HeartbeatAgent implements HttpFunction {

    private static final Logger LOG = Logger.getLogger(HeartbeatAgent.class.getName());

    /**
     * Reusable KMS client to minimize latency during "warm" starts. Initialized
     * once per container instance.
     */
    private static final KeyManagementServiceClient KMS;

    private static final CloudTasksClient TASKS;

    private static final ExecutorService EXECUTOR;

    // Static initialization
    private static final JsonParserFactory JSON_PARSER_FACTORY = Json.createParserFactory(Map.of());
    private static final JsonGeneratorFactory JSON_GENERATOR_FACTORY = Json.createGeneratorFactory(Map.of());

    private static final Storage STORAGE = StorageOptions.getDefaultInstance().getService();

    // Static configuration detected at startup
    private static final KeyRingName KEY_RING;
    private static final QueueName QUEUE;

    // Environment variables
    private static final String BUCKET_NAME;
    private static final String WITNESS_AGENT_URL;

    static {
        BUCKET_NAME = System.getenv("BUCKET_NAME");
        WITNESS_AGENT_URL = System.getenv("WITNESS_AGENT");

        var kmsLocation = System.getenv("KMS_LOCATION");
        var kmsKeyRingName = System.getenv("KMS_KEY_RING");
        var queueLocation = System.getenv("QUEUE_LOCATION");
        var queueName = System.getenv("QUEUE_NAME");

        if (BUCKET_NAME == null || WITNESS_AGENT_URL == null
                || kmsLocation == null || kmsKeyRingName == null
                || queueLocation == null || queueName == null) {
            throw new IllegalStateException("""
                Missing required environment variables. Please ensure:
                BUCKET_NAME, WITNESS_AGENT, KMS_LOCATION, KMS_KEY_RING, QUEUE_LOCATION, QUEUE_NAME are all set.
                """);
        }

        var project = ServiceOptions.getDefaultProjectId();

        KEY_RING = KeyRingName.of(project, kmsLocation, kmsKeyRingName);
        QUEUE = QueueName.of(ServiceOptions.getDefaultProjectId(), queueLocation, queueName);

        try {
            KMS = KeyManagementServiceClient.create();
            TASKS = CloudTasksClient.create();
            EXECUTOR = Executors.newVirtualThreadPerTaskExecutor();

            // Ensure client is closed when the JVM shuts down
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                if (KMS != null) {
                    KMS.close();
                }
                if (TASKS != null) {
                    TASKS.close();
                }
                if (EXECUTOR != null) {
                    EXECUTOR.close();
                }
            }));

            // IAM Validation: Verify KMS, Tasks, and Storage permissions
            var kmsPerms = KMS.testIamPermissions(KEY_RING.toString(),
                    List.of("cloudkms.publicKeys.get", "cloudkms.cryptoKeyVersions.useToSign"))
                    .getPermissionsList();
            if (kmsPerms.size() < 2) {
                throw new IllegalStateException("Missing KMS permissions: " + kmsPerms);
            }

            var taskPerms = TASKS.testIamPermissions(QUEUE.toString(),
                    List.of("cloudtasks.tasks.create"))
                    .getPermissionsList();
            if (taskPerms.size() < 1) {
                throw new IllegalStateException("Missing Tasks permissions: " + taskPerms);
            }

            // GCS Check: Verify read (get) and write/update (create) permissions
            var gcsPerms = STORAGE.testIamPermissions(BUCKET_NAME,
                    List.of("storage.objects.get", "storage.objects.create"));
            if (gcsPerms.size() < 2) {
                throw new IllegalStateException("Missing GCS permissions in bucket " + BUCKET_NAME + ": " + gcsPerms);
            }

            LOG.info("Initialized for " + KEY_RING.toString());

        } catch (IOException e) {
            throw new IllegalStateException("Initialization failed", e);
        }
    }

    @Override
    public void service(HttpRequest request, HttpResponse response) throws Exception {

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            sendError(response, 405, "Method Not Allowed", "HTTP method must be POST.");
            return;
        }

        var futures = new ArrayList<Future<Map<String, String>>>();

        try (final var parser = JSON_PARSER_FACTORY.createParser(request.getInputStream())) {

            if (!parser.hasNext() || parser.next() != JsonParser.Event.START_ARRAY) {
                sendError(response, 400, "Bad Request", "Request body must be a JSON array of heartbeat requests.");
                return;
            }

            while (parser.hasNext()) {

                var next = parser.next();

                if (next == JsonParser.Event.END_ARRAY) {
                    break;
                }

                futures.add(heartbeatAsync(HearbeatRequest.parse(parser, next)));
            }

        } catch (Exception e) {
            // finalize remaining threads if any
            cancelAllRunning(futures);
            sendError(response, 400, "Bad Request", "Failed to parse request: %s".formatted(e.getMessage()));
            return;
        }

        if (futures.isEmpty()) {
            sendError(response, 400, "Bad Request", "No valid heartbeat requests found in the JSON array.");
            return;
        }

        try {
            // Start HTTP response
            response.setStatusCode(200);
            response.setContentType("application/json");

            try (final var gen = JSON_GENERATOR_FACTORY.createGenerator(response.getWriter())) {
                gen.writeStartArray();

                for (var future : futures) {

                    gen.writeStartObject();

                    try {
                        for (var entry : future.get().entrySet()) {
                            gen.write(entry.getKey(), entry.getValue());
                        }

                    } catch (ExecutionException | InterruptedException e) {
                        gen.write("status", "Error");
                        gen.write("message", e.getMessage());
                    }

                    gen.writeEnd();
                }
                gen.writeEnd();
            }
            return;

        } catch (IllegalArgumentException e) {
            sendError(response, 400, "Bad Request",
                    "Invalid heartbeat request structure: %s".formatted(e.getMessage()));

        } catch (Exception e) {
            sendError(response, 500, "Internal Server Error",
                    "Unexpected error occurred: %s".formatted(e.getMessage()));
        }

        // finalize remaining threads if any
        cancelAllRunning(futures);
    }

    private Future<Map<String, String>> heartbeatAsync(final HearbeatRequest request) {

        final var kmsKeyResource = KEY_RING.toString()
                + "/cryptoKeys/"
                + request.resource();

        return ApiFutures.transform(ApiFutures.transformAsync(
                ApiFutures.allAsList(Arrays.asList(
                        getCryptoSuiteAsync(kmsKeyResource),
                        getEventLogAsync(request))),
                results -> {
                    var suite = (CryptoSuite) results.get(0);
                    EventLog log = (EventLog) results.get(1);

                    var lastEventHash = log.lastEventHash();

                    var unsignedEvent = Map.of(
                            "previousEventHash", lastEventHash,
                            "operation", Map.of("type", "heartbeat"));

                    // sign the event
                    var proof = suite.sign(
                            kmsKeyResource,
                            unsignedEvent,
                            request.did() + request.assertionMethod());

                    var signedEvent = new LinkedHashMap<>(unsignedEvent);
                    signedEvent.put("proof", proof);

                    log.appendEvent(signedEvent);

                    storeLog(request.did().substring("did:cel:".length()),
                            log.generation(),
                            log.asByteArray(JSON_GENERATOR_FACTORY));

                    return taskWitnessAgentAsync(request.did(), request.witnesses());
                },
                MoreExecutors.directExecutor()),
                task -> Map.of(
                        "id", request.did(),
                        "witnessAgentTask", task.getName(),
                        "dbgWitnessAgentTask", task.toString()),
                MoreExecutors.directExecutor());
    }

    private static ApiFuture<CryptoSuite> getCryptoSuiteAsync(final String kmsKeyResource) {
        return ApiFutures.transform(
                KMS.getPublicKeyCallable()
                        .futureCall(GetPublicKeyRequest.newBuilder()
                                .setName(kmsKeyResource)
                                .build()),
                publicKey -> CryptoSuite.newSuite(publicKey.getAlgorithm(), KMS),
                MoreExecutors.directExecutor());
    }

    private static ApiFuture<Task> taskWitnessAgentAsync(String di, List<String> witnesses) {

        final var requestBody = new StringBuilder()
                .append("{\"id\":")
                .append(Json.createValue(di).toString())
                .append(",\"witnessEndpoint\":[")
                .append(witnesses.stream()
                        .map(Json::createValue)
                        .map(Object::toString)
                        .collect(Collectors.joining(",")))
                .append("]}")
                .toString();

        final var task = Task.newBuilder()
                .setHttpRequest(com.google.cloud.tasks.v2.HttpRequest.newBuilder()
                        .setBody(ByteString.copyFrom(requestBody, StandardCharsets.UTF_8))
                        .setHttpMethod(HttpMethod.POST)
                        .setUrl(WITNESS_AGENT_URL)
                        .putHeaders("Content-Type", "application/json")
                        .build())
                .build();

        return TASKS.createTaskCallable().futureCall(CreateTaskRequest.newBuilder()
                .setParent(QUEUE.toString())
                .setTask(task)
                .build());
    }

    private void storeLog(String id, long generation, byte[] log) {
        // Minimal write: storage.create() only requires roles/storage.objectCreator
        STORAGE.create(BlobInfo.newBuilder(BlobId.of(BUCKET_NAME, id))
                .setContentType("application/json")
                .build(), log, Storage.BlobTargetOption.generationMatch(generation));
    }

    private static ApiFuture<EventLog> getEventLogAsync(HearbeatRequest request) {
        final SettableApiFuture<EventLog> future = SettableApiFuture.create();

        EXECUTOR.execute(() -> {
            try {
                final var blobId = BlobId.of(BUCKET_NAME, request.did().substring("did:cel:".length()));
                Blob blob = STORAGE.get(blobId); // This blocks, but Virtual Threads handle it

                future.set(EventLog.parse(blob, JSON_PARSER_FACTORY));

            } catch (Exception e) {
                future.setException(e);
            }
        });

        return future;
    }

    private static void sendError(HttpResponse response, int code, String status, String message) throws IOException {
        response.setStatusCode(code, status);
        response.setContentType("application/json");

        try (final var gen = JSON_GENERATOR_FACTORY.createGenerator(response.getWriter())) {
            gen.writeStartObject()
                    .write("status", status)
                    .write("message", message)
                    .writeEnd();
        }
    }

    private static void cancelAllRunning(Collection<? extends Future<?>> futures) {
        // finalize remaining threads if any
        for (var future : futures) {
            if (future.state() == Future.State.RUNNING) {
                future.cancel(true);
            }
        }
    }
}

record HearbeatRequest(
        String did,
        String assertionMethod,
        String resource,
        List<String> witnesses) {

    public static HearbeatRequest parse(JsonParser parser, JsonParser.Event event) {

        if (event != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException(
                    "Expected JSON object for heartbeat request, but got %s".formatted(event));
        }

        String did = null;
        String resource = null;
        String method = null;

        List<String> witnesses = List.of();

        while (parser.hasNext()) {
            var next = parser.next();
            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }
            // In OBJECT context, next is always KEY_NAME
            String key = parser.getString();

            switch (key) {
            case "id":
                parser.next();
                did = parser.getString();
                break;

            case "assertionMethod":
                if (parser.next() != Event.START_OBJECT) {
                    throw new IllegalArgumentException("Property 'assertionMethod' must be a JSON object.");
                }

                while (parser.hasNext()) {
                    if (parser.next() == JsonParser.Event.END_OBJECT) {
                        break;
                    }
                    switch (parser.getString()) {
                    case "id":
                        parser.next();
                        method = parser.getString();
                        break;
                    case "resource":
                        parser.next();
                        resource = parser.getString().substring("kms:".length());
                    }
                }
                break;

            case "witnessEndpoint":
                witnesses = parseStringList(parser);
                break;

            default:
                throw new IllegalArgumentException();
            }
        }

        return new HearbeatRequest(did, method, resource, witnesses);
    }

    private static List<String> parseStringList(JsonParser parser) {

        final var event = parser.next();

        if (event != Event.START_ARRAY) {
            throw new IllegalArgumentException("Expected start array event, but got %s".formatted(event));
        }

        final var list = new ArrayList<String>();

        while (parser.hasNext()) {
            if (parser.next() == JsonParser.Event.END_ARRAY) {
                break;
            }
            list.add(parser.getString());
        }

        return list;
    }
}