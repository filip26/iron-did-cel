package com.apicatalog.cel;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonParser;

class Operation {

    private final String type;
    private final Map<String, Object> data;

    public Operation(String type, Map<String, Object> data) {
        this.type = type;
        this.data = data;
    }

    public static Operation read(JsonParser parser) {
        if (!parser.hasNext() || parser.next() != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("Event must be a JSON object.");
        }

        String type = null;
        Map<String, Object> data = null;

        while (parser.hasNext()) {

            var next = parser.next();

            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }

            switch (parser.getString()) {
            case "type":
                if (parser.next() != JsonParser.Event.VALUE_STRING) {
                    throw new IllegalArgumentException("Even log operation type must be string");
                }
                type = parser.getString();
                break;

            case "data":
                data = readMap(parser);
                break;

            case String unknown:
                throw new IllegalArgumentException(
                        "An unknown request property '%s' has been detected".formatted(unknown));
            }
        }

        return new Operation(type, data);
    }

    public void write(JsonGenerator gen) {
        gen.writeStartObject();
        gen.write("type", type);
        if (data != null) {
            gen.writeKey("data");
            write(data, gen);
        }
        gen.writeEnd();
    }

    public String type() {
        return type;
    }

    public Map<String, Object> data() {
        return data;
    }

    static void write(Object value, JsonGenerator gen) {
        if (value == null) {
            gen.writeNull();
            return;
        }

        if (value instanceof Boolean bool) {
            gen.write(bool);
            return;
        }

        if (value instanceof String string) {
            gen.write(string);
            return;
        }

        if (value instanceof BigDecimal number) {
            gen.write(number);
        }

        if (value instanceof Map<?, ?> map) {
            gen.writeStartObject();
            for (var entry : map.entrySet()) {
                gen.writeKey((String) entry.getKey());
                write(entry.getValue(), gen);
            }
            gen.writeEnd();
            return;
        }

        if (value instanceof Collection<?> array) {
            gen.writeStartArray();
            for (var el : array) {
                write(el, gen);
            }
            gen.writeEnd();
        }
    }

    static Map<String, Object> readMap(JsonParser parser) {

        if (!parser.hasNext() || parser.next() != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("A document root must be a JSON object");
        }

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
        return map;
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
}
