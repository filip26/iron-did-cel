
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import com.apicatalog.multibase.Multibase;
import com.google.cloud.ServiceOptions;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;

import jakarta.json.Json;
import jakarta.json.stream.JsonGeneratorFactory;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParser.Event;
import jakarta.json.stream.JsonParserFactory;

/**
 * A Google Cloud Function that provides digital signatures using Google Cloud
 * Key Management Service (KMS).
 * 
 * <h3>Required Environment Variables:</h3>
 * <ul>
 * <li><code>KMS_LOCATION</code> - The GCP region of the KeyRing (e.g.,
 * us-central1).</li>
 * <li><code>KMS_KEY_RING</code> - The name of the KMS KeyRing.</li>
 * <li><code>KMS_KEY_ID</code> - The name of the Asymmetric Signing Key.</li>
 * <li><code>KMS_KEY_VERSION</code> - (Optional) The version of the key.
 * Defaults to "1".</li>
 * <li><code>C14N</code> - The canonicalization, JCS or RDFC.</li>
 * </ul>
 */
public class WitnessService implements HttpFunction {

    private static final Logger LOG = Logger.getLogger(WitnessService.class.getName());

    /**
     * Reusable KMS client to minimize latency during "warm" starts. Initialized
     * once per container instance.
     */
    private static final KeyManagementServiceClient KMS;

    // Static initialization
    private static final JsonParserFactory JSON_PARSER = Json.createParserFactory(Map.of());
    private static final JsonGeneratorFactory JSON_GENERATOR = Json.createGeneratorFactory(Map.of());

    // Environment variables
    private static final String VERIFICATION_METHOD;

    // Static configuration detected at startup
    private static final String KMS_RESOURCE;
    private static final CryptoSuite CRYPTOSUITE;

    static {
        var location = System.getenv("KMS_LOCATION");
        var keyRing = System.getenv("KMS_KEY_RING");
        var keyId = System.getenv("KMS_KEY_ID");

        var version = System.getenv().getOrDefault("KMS_KEY_VERSION", "1");
        var c14n = System.getenv("C14N");

        VERIFICATION_METHOD = System.getenv("VERIFICATION_METHOD");

        if (location == null || keyRing == null || keyId == null || VERIFICATION_METHOD == null || c14n == null) {
            throw new IllegalStateException("Incomplete environment configuration");
        }

        var project = ServiceOptions.getDefaultProjectId();

        KMS_RESOURCE = CryptoKeyVersionName.format(
                project,
                location,
                keyRing,
                keyId,
                version);

        try {
            KMS = KeyManagementServiceClient.create();

            // Ensure client is closed when the JVM shuts down
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                if (KMS != null) {
                    KMS.close();
                }
            }));

        } catch (IOException e) {
            throw new IllegalStateException("KMS initialization failed", e);
        }

        // IAM Validation: Verify KMS
        var kmsPerms = KMS.testIamPermissions(KMS_RESOURCE,
                List.of("cloudkms.publicKeys.get", "cloudkms.cryptoKeyVersions.useToSign"))
                .getPermissionsList();
        if (kmsPerms.size() < 2) {
            throw new IllegalStateException("Missing KMS permissions: " + kmsPerms);
        }

        // Get key algorithm from a public key, cloudkms.publicKeyViewer is least
        // permissive
        final var publicKey = KMS.getPublicKey(KMS_RESOURCE);

        final var keyAlgorithm = publicKey.getAlgorithm();

        CRYPTOSUITE = CryptoSuite.newSuite(keyAlgorithm, c14n, KMS);

        LOG.info("Initialized for %s with %s (%dB bytes)".formatted(
                CRYPTOSUITE.name(),
                KMS_RESOURCE,
                CRYPTOSUITE.keyLength()));
    }

    @Override
    public void service(HttpRequest request, HttpResponse response) throws Exception {

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            sendError(response, 405, "Method Not Allowed", "HTTP method must be POST.");
            return;
        }

        final String digestMultibase;

        try (final var parser = JSON_PARSER.createParser(request.getInputStream())) {

            if (!parser.hasNext() || parser.next() != JsonParser.Event.START_OBJECT) {
                sendError(response, 400, "Bad Request", "Request body must be a JSON object of witness requests.");
                return;
            }

            digestMultibase = parseWitnessRequest(parser);

        } catch (Exception e) {
            sendError(response, 400, "Bad Request", e.getMessage());
            return;
        }

        if (digestMultibase == null
                || digestMultibase.isBlank()
                || !Multibase.BASE_58_BTC.isEncoded(digestMultibase)
                        && !Multibase.BASE_64_URL.isEncoded(digestMultibase)) {
            sendError(response, 400, "Bad Request",
                    "Property 'digestMultibase' value must be multibase encoded string, base58btc or base64URLnopad");
            return;
        }

        try {
            // sign the digest and create a new W3C VC Data Integrity proof
            var proof = CRYPTOSUITE.sign(KMS_RESOURCE, digestMultibase, VERIFICATION_METHOD);

            // set response headers
            response.setStatusCode(200);
            response.setContentType("application/json");

            try (final var writer = response.getWriter()) {
                // write the data integrity proof serialized as JSON
                proof.write(writer);
            }

        } catch (Exception e) {
            LOG.severe("Signing Failed: " + e.getMessage());
            sendError(response, 500, "Signing Failed", e.getMessage());
        }
    }

    private static void sendError(HttpResponse response, int code, String status, String message) throws IOException {
        response.setStatusCode(code);
        response.setContentType("application/json");

        try (final var gen = JSON_GENERATOR.createGenerator(response.getWriter())) {
            gen.writeStartObject()
                    .write("status", status)
                    .write("message", message)
                    .writeEnd();
        }
    }

    private static String parseWitnessRequest(JsonParser parser) {
        while (parser.hasNext()) {

            var next = parser.next();

            if (next == Event.END_OBJECT) {
                break;
            }
            
            // In OBJECT context, next is always KEY_NAME
            
            if (!"digestMultibase".equals(parser.getString())) {
                throw new IllegalArgumentException(
                        "An unknown property '%s' has been detected".formatted(parser.getString()));
            }

            if (parser.next() == Event.VALUE_STRING) {
                return parser.getString();
            }

            throw new IllegalArgumentException(
                    "Property 'digestMultibase' value must be JSON string, but got %s"
                            .formatted(parser.currentEvent()));
        }
        throw new IllegalArgumentException("The request does not contain 'digestMultibase' property");
    }
}
