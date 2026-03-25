import java.util.ArrayList;
import java.util.List;

import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParser.Event;

class WitnessAgentRequest {

    private final String did;
    private final List<String> witnessEndpoints;

    public WitnessAgentRequest(String did, List<String> witnessEndpoints) {
        this.did = did;
        this.witnessEndpoints = witnessEndpoints;
    }

    public static final WitnessAgentRequest parse(JsonParser parser) {

        if (!parser.hasNext() || parser.next() != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("Request body must be a JSON object.");
        }

        String did = null;
        List<String> witnessEndpoints = null;

        while (parser.hasNext()) {

            var next = parser.next();

            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }

            switch (parser.getString()) {
            case "id":
                if (parser.next() != JsonParser.Event.VALUE_STRING) {
                    throw new IllegalArgumentException("Property 'id' must be JSON string.");
                }
                did = parser.getString();
                break;

            case "witnessEndpoint":
                witnessEndpoints = parseStringList(parser);
                break;

            case String unknown:
                throw new IllegalArgumentException(
                        "An unknown request property '%s' has been detected".formatted(unknown));
            }
        }

        if (did == null) {
            throw new IllegalArgumentException("Required property 'did' is missing");
        }

        if (!did.startsWith("did:cel:")) {
            throw new IllegalArgumentException("Unsupported did method [" + did + "]");
        }

        if (witnessEndpoints == null || witnessEndpoints.isEmpty()) {
            throw new IllegalArgumentException("No witness endpoint is defined");
        }

        return new WitnessAgentRequest(did, witnessEndpoints);
    }

    public String did() {
        return did;
    }

    public List<String> witnessEndpoints() {
        return witnessEndpoints;
    }

    private static List<String> parseStringList(JsonParser parser) {

        final var event = parser.next();

        if (event != Event.START_ARRAY) {
            throw new IllegalArgumentException("Expected start array event, but got %s".formatted(event));
        }

        final var list = new ArrayList<String>();

        while (parser.hasNext()) {
            var next = parser.next();
            if (next == JsonParser.Event.END_ARRAY) {
                break;
            }
            if (next != JsonParser.Event.VALUE_STRING) {
                throw new IllegalArgumentException("Expected string, but got %s".formatted(next));
            }
            list.add(parser.getString());
        }

        return list;
    }
}
