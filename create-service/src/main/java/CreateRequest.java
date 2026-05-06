import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.google.cloud.kms.v1.PublicKey;

import jakarta.json.stream.JsonParser;

class Document {

    private final Map<String, Object> document;

    private final String assertionKmsKeyId;
    private final List<Map<String, String>> kmsKeys;

    private Entry<Entry<String, String>, PublicKey> assertionKey;

    private Document(
            Map<String, Object> document,
            String assertionKmsKeyId,
            List<Map<String, String>> kmsKeys
    ) {
        this.document = document;
        this.assertionKmsKeyId = assertionKmsKeyId;
        this.kmsKeys = kmsKeys;
        this.assertionKey = null;
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
            document.put("heartbeatFrequency", "P3M");
        }

        var verificationMethod = document.get("verificationMethod");
        final List<Object> methods;

        if (verificationMethod instanceof List list) {
            methods = list;

        } else if (verificationMethod != null) {
            methods = List.of(verificationMethod);

        } else {
            methods = List.of();
        }

        String assertionKmsKeyId = null;

        final var kmsKeys = new ArrayList<Map<String, String>>();
        final var kmsRefs = new HashMap<String, String>();

        for (final var method : methods) {
            if (method instanceof Map kmsKey
                    && kmsKey.get("resource") instanceof String resource
                    && resource.startsWith("kms:")) {

                kmsKeys.add(kmsKey);

                if (kmsKey.get("id") instanceof String id) {
                    kmsRefs.put(id, resource);
                }
            }
        }

        for (final var entry : document.entrySet()) {

            switch (entry.getKey()) {
            case "assertionMethod",
                    "authentication",
                    "keyAgreement",
                    "capabilityInvocation",
                    "capabilityDelegation",
                    "recovery":

                final List<Object> values;

                if (entry.getValue() instanceof List list) {
                    values = list;

                } else if (entry.getValue() != null) {
                    values = List.of(entry.getValue());

                } else {
                    values = List.of();
                }

                for (var value : values) {
                    if (assertionKmsKeyId == null
                            && "assertionMethod".equals(entry.getKey())
                            && value instanceof String keyRef
                            && kmsRefs.get(keyRef) instanceof String resource) {

                        assertionKmsKeyId = resource;

                    } else if (value instanceof Map kmsKey
                            && kmsKey.get("resource") instanceof String resource
                            && resource.startsWith("kms:")) {

                        if (assertionKmsKeyId == null && "assertionMethod".equals(entry.getKey())) {
                            assertionKmsKeyId = resource;
                        }

                        kmsKeys.add(kmsKey);
                    }
                }

            default:
                continue;
            }
        }

        if (assertionKmsKeyId == null) {
            throw new IllegalArgumentException("Missing assertionMethod KMS key.");
        }

        return new Document(document, assertionKmsKeyId, kmsKeys);
    }

    public void bind(final Map<String, Entry<Entry<String, String>, PublicKey>> keyMap) {

        for (var kmsKey : kmsKeys) {

            var kmsKeyId = kmsKey.get("resource");

            var keyEntry = keyMap.get(kmsKeyId);

            if (assertionKmsKeyId.equals(kmsKeyId)) {
                assertionKey = keyEntry;
            }

            Document.overrideWithMultikey(
                    kmsKey,
                    keyEntry.getKey().getKey(),
                    keyEntry.getKey().getValue());
        }

        if (assertionKey == null) {
            throw new IllegalStateException("Unmatched assertionMethod KMS key.");
        }
    }

    public Map<String, Object> update(String did) {
        document.put("id", did);
        for (var key : kmsKeys) {
            key.put("controller", did);
        }
        return document;
    }

    public Map<String, Object> root() {
        return document;
    }
    
    public List<Map<String, String>> kmsKeys() {
        return kmsKeys;
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
        default -> null;
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

    public PublicKey publicKey() {
        return assertionKey.getValue();
    }

    public String publicKeyFragmentId() {
        return assertionKey.getKey().getKey();
    }
}
