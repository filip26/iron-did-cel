import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutures;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.cloud.kms.v1.PublicKey;
import com.google.cloud.kms.v1.PublicKey.PublicKeyFormat;
import com.google.common.util.concurrent.MoreExecutors;

import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParser.Event;

class Document {

    private final String id;
    private final Map<String, Object> document;
    private final List<Map<String, String>> kmsKeys;

    private Document(
            String id,
            Map<String, Object> document,
            List<Map<String, String>> kmsKeys) {
        this.id = id;
        this.document = document;
        this.kmsKeys = kmsKeys;
    }

    // assembly initial did document
    public static Document read(JsonParser parser) {

        if (!parser.hasNext() || parser.next() != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("Root must be a JSON object");
        }

        var document = new LinkedHashMap<String, Object>();

        document.put("@context", List.of(
                "https://www.w3.org/ns/did/v1.1",
                "https://w3id.org/didcel/v1"));

        while (parser.hasNext()) {
            var next = parser.next();
            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }
            String key = parser.getString();
            document.put(key, processEvent(parser, parser.next()));
        }

        if (!document.containsKey("assertionMethod")) {
            throw new IllegalArgumentException("The assertionMethod is not defined.");
        }

        if (!document.containsKey("service")) {
            throw new IllegalArgumentException("A service is not defined.");
        }

        if (!document.containsKey("heartbeatFrequency")) {
            throw new IllegalArgumentException("A heartbeatFrequency is not defined.");
        }

        String id = null;
        final var kmsKeys = new ArrayList<Map<String, String>>();

        // scan for document id and KMS keys to bind
        for (final var entry : document.entrySet()) {

            switch (entry.getKey()) {
            // document id property
            case "id":
                if (entry.getValue() instanceof String stringId) {
                    id = stringId;

                } else {
                    throw new IllegalArgumentException("The document 'id' must be JSON string");
                }
                break;

            // expect KSM keys occurrence
            case "assertionMethod",
                    "authentication",
                    "keyAgreement",
                    "capabilityInvocation",
                    "capabilityDelegation",
                    "recovery",
                    "verificationMethod":

                final var values = entry.getValue() instanceof List list
                        ? list
                        : entry.getValue() != null
                                ? List.of(entry.getValue())
                                : List.of();

                for (var value : values) {
                    if (value instanceof Map kmsKey
                            && kmsKey.get("resource") instanceof String resource
                            && resource.startsWith("urn:kms:")) {

                        kmsKeys.add(kmsKey);
                    }
                }

            default:
                continue;
            }
        }

        if (id == null) {
            throw new IllegalArgumentException("The document has no 'id' property");
        }

        return new Document(id, document, kmsKeys);
    }

    public final void bindKeys(
            final KeyManagementServiceClient kms,
            final KeyRingName kmsKeyRing,
            final boolean isPostQuantum) throws InterruptedException, ExecutionException {

        if (kmsKeys.isEmpty()) {
            return;
        }

        // <urn:kms:id, <kms:id, <<Multikey.id, Multikey.multibase>, publicKey>
        final var futureMap = new LinkedHashMap<String, ApiFuture<Entry<String, Entry<Entry<String, String>, PublicKey>>>>(
                kmsKeys.size());

        for (var kmsKey : kmsKeys) {
            var kmsKeyResource = kmsKey.get("resource");

            if (futureMap.containsKey(kmsKeyResource)) {
                continue;
            }

            final var resourceName = kmsKeyRing.toString() + "/cryptoKeys/"
                    + kmsKeyResource.substring("urn:kms:".length());

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
        var keyMap = ApiFutures.allAsList(futureMap.values()).get().stream()
                .collect(Collectors.toMap(
                        Entry::getKey,
                        Entry::getValue));

        for (var kmsKey : kmsKeys) {

            var kmsKeyId = kmsKey.get("resource");

            var keyEntry = keyMap.get(kmsKeyId);

            Document.overrideWithMultikey(
                    kmsKey,
                    keyEntry.getKey().getKey(),
                    keyEntry.getKey().getValue());
        }
    }

    public Map<String, Object> asMap() {
        return document;
    }

    private static Object processEvent(JsonParser parser, JsonParser.Event event) {
        return switch (event) {
        case START_OBJECT -> {
            var map = new LinkedHashMap<String, Object>();
            while (parser.hasNext()) {
                var next = parser.next();
                if (next == JsonParser.Event.END_OBJECT) {
                    break;
                }
                // In OBJECT context, next is always KEY_NAME
                String key = parser.getString();
                map.put(key, processEvent(parser, parser.next()));
            }
            yield map;
        }
        case START_ARRAY -> {
            var list = new ArrayList<>();
            while (parser.hasNext()) {
                var next = parser.next();
                if (next == JsonParser.Event.END_ARRAY) {
                    break;
                }
                list.add(processEvent(parser, next));
            }
            yield list;
        }
        case VALUE_STRING -> parser.getString();
        case VALUE_NUMBER -> parser.getBigDecimal();
        case VALUE_TRUE -> Boolean.TRUE;
        case VALUE_FALSE -> Boolean.FALSE;
        case VALUE_NULL -> null;
        case Event unknown -> throw new IllegalStateException("Unknown JsonParser event [" + unknown + "]");
        };
    }

    private static void overrideWithMultikey(
            Map<String, String> map,
            String id,
            String publicKeyMultibase) {

        map.put("id", id);
        map.put("type", "Multikey");
        map.put("publicKeyMultibase", publicKeyMultibase);
        map.remove("resource");
    }

    public String id() {
        return id;
    }
}
