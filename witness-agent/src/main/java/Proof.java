import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.json.stream.JsonParser;

class Proof {

    public static List<Map<String, String>> readList(JsonParser parser) {

        if (!parser.hasNext()) {
            throw new IllegalArgumentException("Invalid 'proof' property value, no proof(s) found");
        }

        var event = parser.next();

        if (event == JsonParser.Event.START_OBJECT) {
            return List.of(read(parser, event));
        }

        if (event != JsonParser.Event.START_ARRAY) {
            throw new IllegalArgumentException("Invalid 'proof' property value, should be an array of proofs");
        }

        var list = new ArrayList<Map<String, String>>();

        while (parser.hasNext()) {
            var next = parser.next();
            if (next == JsonParser.Event.END_ARRAY) {
                break;
            }
            list.add(read(parser, next));
        }
        return list;
    }

    static Map<String, String> read(JsonParser parser, JsonParser.Event parserEvent) {

        if (!parser.hasNext() || parserEvent != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException(
                    "A document root must be a JSON object, but got %s".formatted(parserEvent));
        }

        var map = new LinkedHashMap<String, String>();
        while (parser.hasNext()) {
            var next = parser.next();
            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }
            // In OBJECT context, next is always KEY_NAME
            String key = parser.getString();

            if (parser.next() != JsonParser.Event.VALUE_STRING) {
                throw new IllegalArgumentException("Only strings are supported as proof object values");
            }
            map.put(key, parser.getString());
        }
        return map;
    }
}
