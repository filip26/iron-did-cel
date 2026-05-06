
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.apicatalog.tree.io.jakarta.JakartaGenerator;
import com.apicatalog.tree.io.java.JavaAdapter;
import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutures;
import com.google.cloud.ServiceOptions;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.cloud.kms.v1.PublicKey;
import com.google.cloud.kms.v1.PublicKey.PublicKeyFormat;
import com.google.common.util.concurrent.MoreExecutors;

import jakarta.json.Json;
import jakarta.json.JsonException;
import jakarta.json.stream.JsonGeneratorFactory;
import jakarta.json.stream.JsonParserFactory;

public class CreateService implements HttpFunction {

    private static final Logger LOG = Logger.getLogger(CreateService.class.getName());

    /**
     * Reusable KMS client to minimize latency during "warm" starts. Initialized
     * once per container instance.
     */
    private static final KeyManagementServiceClient KMS_CLIENT;

    // Static initialization
    private static final JsonParserFactory JSON_PARSER_FACTORY = Json.createParserFactory(Map.of());
    private static final JsonGeneratorFactory JSON_GENERATOR_FACTORY = Json.createGeneratorFactory(Map.of());

    // Static configuration detected at startup
    private static final KeyRingName KEY_RING;

    // Environment variables
    private static final boolean IS_POST_QUANTUM;

    static {
        var kmsLocation = System.getenv("KMS_LOCATION");
        var kmsKeyRingName = System.getenv("KMS_KEY_RING");

        if (kmsLocation == null || kmsKeyRingName == null) {
            throw new IllegalStateException("Incomplete environment configuration");
        }

        IS_POST_QUANTUM = Boolean.valueOf(System.getenv().getOrDefault("PQ", "false"));

        var project = ServiceOptions.getDefaultProjectId();

        KEY_RING = KeyRingName.of(project, kmsLocation, kmsKeyRingName);

        try {

            KMS_CLIENT = KeyManagementServiceClient.create();

            // Ensure client is closed when the JVM shuts down
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                if (KMS_CLIENT != null) {
                    KMS_CLIENT.close();
                }
            }));

            // IAM Validation: Verify KMS
            var kmsPermissions = KMS_CLIENT.testIamPermissions(KEY_RING,
                    List.of("cloudkms.cryptoKeyVersions.viewPublicKey",
                            "cloudkms.cryptoKeyVersions.useToSign"));
            if (kmsPermissions.getPermissionsList().size() < 2) {
                throw new IllegalStateException("Missing KMS permissions: " + kmsPermissions);
            }

            LOG.info(String.format("Initialized for %s", KEY_RING.toString()));

        } catch (IOException e) {
            throw new IllegalStateException("KMS initialization failed", e);
        }
    }

    @Override
    public void service(HttpRequest request, HttpResponse response) throws Exception {

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            sendError(response, 405, "Method Not Allowed", "Use POST");
            return;
        }

        final Document document;

        try (final var parser = JSON_PARSER_FACTORY.createParser(request.getInputStream())) {

            document = Document.read(parser);

        } catch (JsonException | IllegalArgumentException e) {
            sendError(response, 400, "Bad Request", e.getMessage());
            return;

        } catch (Exception e) {
            sendError(response, 400, "Bad Request", "Malformatted body");
            return;
        }

        try {

            document.bind(getKeys(document.kmsKeys(), KMS_CLIENT, KEY_RING, IS_POST_QUANTUM));

            // create new did:cel:method-specific-id
            final var methodSpecificId = EventLog.methodSpecificId(document.root());

            // create the did:cel identifier
            final var did = "did:cel:" + methodSpecificId;

            // update initial DID document
            document.update(did);

            // assembly initial create operation
            final var operation = EventLog.newOperation("create", document.root());

            // the initial create event
            final var event = new LinkedHashMap<String, Object>();
            event.put("operation", operation);

            // proof verification method
            final var verificationMethod = did + document.publicKeyFragmentId();

            final var suite = CryptoSuite.newSuite(document.publicKey(), KMS_CLIENT);

            // sign the event
            final var proof = suite.sign(event, verificationMethod);

            // add proof the event
            event.put("proof", List.of(proof));

            // assembly initial log
            final var log = EventLog.newLog(event);

            response.setStatusCode(200, "OK");
            response.setContentType("application/json");

            // serialize as JSON
            try (final var gen = JSON_GENERATOR_FACTORY.createGenerator(response.getOutputStream())) {
                final var writer = new JakartaGenerator(gen);
                writer.node(log, JavaAdapter.instance());
            }

        } catch (IllegalArgumentException e) {
            sendError(response, 400, "Bad Request", e.getMessage());

        } catch (Exception e) {
            LOG.severe(e.getMessage());
            sendError(response, 500, "Internal Error", e.getMessage());
        }
    }

    private final Map<String, Entry<Entry<String, String>, PublicKey>> getKeys(
            List<Map<String, String>> kmsKeys,
            final KeyManagementServiceClient kms,
            final KeyRingName kmsKeyRing,
            final boolean isPostQuantum) throws InterruptedException, ExecutionException {

        // <kms:id, <kms:id, <<Multikey.id, Multikey.multibase>, publicKey>
        final var futureMap = new LinkedHashMap<String, ApiFuture<Entry<String, Entry<Entry<String, String>, PublicKey>>>>(
                kmsKeys.size());

        for (var kmsKey : kmsKeys) {
            var kmsKeyResource = kmsKey.get("resource");

            if (futureMap.containsKey(kmsKeyResource)) {
                continue;
            }

            final var resourceName = kmsKeyRing.toString() + "/cryptoKeys/" + kmsKeyResource.substring("kms:".length());

            futureMap.put(kmsKeyResource, ApiFutures.transform(
                    kms
                            .getPublicKeyCallable()
                            .futureCall(GetPublicKeyRequest.newBuilder()
                                    .setName(resourceName)
                                    .setPublicKeyFormat(
                                            isPostQuantum
                                                    ? PublicKeyFormat.NIST_PQC
                                                    : PublicKeyFormat.PUBLIC_KEY_FORMAT_UNSPECIFIED)
                                    .build()),
                    publicKey -> {

                        var publicKeyMultibase = PublicKeyExporter.publicMultikey(publicKey);

                        return Map.entry(
                                kmsKeyResource,
                                Map.entry(
                                        Map.entry(
                                                kmsKey.get("id") != null
                                                        ? kmsKey.get("id")
                                                        : "#" + PublicKeyExporter.fingerprint(
                                                                publicKey,
                                                                publicKeyMultibase),
                                                publicKeyMultibase),
                                        publicKey));
                    },
                    MoreExecutors.directExecutor()));
        }

        // Combine all individual string futures into one list future
        return ApiFutures.allAsList(futureMap.values()).get().stream()
                .collect(Collectors.toMap(
                        Entry::getKey,
                        Entry::getValue));
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
}
