package com.apicatalog.cel.io;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.apicatalog.cel.Event;
import com.apicatalog.cel.EventEntry;
import com.apicatalog.cel.EventLog;
import com.apicatalog.cel.Operation;

import jakarta.json.Json;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParserFactory;

public class JakartaEventLogReader implements EventLogReader {

    private final JsonParserFactory parserFactory;

    public JakartaEventLogReader() {
        this(Json.createParserFactory(Map.of()));
    }

    public JakartaEventLogReader(JsonParserFactory parserFactory) {
        this.parserFactory = parserFactory;
    }

    @Override
    public EventLog read(String contentType, InputStream content) {
        try (var parser = parserFactory.createParser(content)) {
            return parse(parser);
        }
    }

    public static final EventLog parse(JsonParser parser) {

        if (!parser.hasNext() || parser.next() != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("Event log body must be a JSON object.");
        }

        final var events = new ArrayList<EventEntry>();

        while (parser.hasNext()) {

            var next = parser.next();

            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }

            switch (parser.getString()) {
            case "log":
                if (parser.next() != JsonParser.Event.START_ARRAY) {
                    throw new IllegalArgumentException("Event log entry must be an array event");
                }

                while (parser.hasNext()) {
                    var parserEvent = parser.next();

                    if (parserEvent == JsonParser.Event.END_ARRAY) {
                        break;
                    }
                    events.add(parseEventEntry(parser, parserEvent));
                }
                break;

            case String unknown:
                throw new IllegalArgumentException(
                        "An unknown request property '%s' has been detected".formatted(unknown));
            }
        }

        return new EventLog(events);
    }
    
    public static EventEntry parseEventEntry(JsonParser parser, JsonParser.Event parserEvent) {
        if (!parser.hasNext() || parserEvent != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("Event must be a JSON object, but got %s".formatted(parserEvent));
        }

        Event event = null;
        List<Map<String, String>> proofs = null;

        while (parser.hasNext()) {

            var next = parser.next();

            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }

            switch (parser.getString()) {
            case "event":
                event = parseEvent(parser, parser.next());
                break;

            case "proof":
                proofs = parseProofs(parser);
                break;

            case String unknown:
                throw new IllegalArgumentException(
                        "An unknown request property '%s' has been detected".formatted(unknown));
            }
        }

        if (event == null) {
            throw new IllegalArgumentException("Event entry does not contain an event object");
        }

        return new EventEntry(event, proofs == null || proofs.isEmpty() ? null : proofs);
    }
    

    public static Event parseEvent(JsonParser parser, JsonParser.Event parserEvent) {
        if (!parser.hasNext() || parserEvent != JsonParser.Event.START_OBJECT) {
            throw new IllegalArgumentException("Event must be a JSON object, but got %s".formatted(parserEvent));
        }

        String previousEventHash = null;
        Operation operation = null;
        List<Map<String, String>> proofs = null;

        while (parser.hasNext()) {

            var next = parser.next();

            if (next == JsonParser.Event.END_OBJECT) {
                break;
            }

            switch (parser.getString()) {
            case "previousEventHash":
                if (parser.next() != JsonParser.Event.VALUE_STRING) {
                    throw new IllegalArgumentException("Event log previousEventHash property must be string");
                }
                previousEventHash = parser.getString();
                break;

            case "operation":
                operation = parseOperation(parser);
                break;

            case "proof":
                proofs = parseProofs(parser);
                break;

            case String unknown:
                throw new IllegalArgumentException(
                        "An unknown property '%s' has been detected".formatted(unknown));
            }
        }

        return new Event(previousEventHash, operation, proofs);
    }

    public static Operation parseOperation(JsonParser parser) {
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
                data = parseData(parser);
                break;

            case String unknown:
                throw new IllegalArgumentException(
                        "An unknown request property '%s' has been detected".formatted(unknown));
            }
        }

        return new Operation(type, data);
    }
    
    public static Map<String, Object> parseData(JsonParser parser) {

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

    public static List<Map<String, String>> parseProofs(JsonParser parser) {

        if (!parser.hasNext()) {
            throw new IllegalArgumentException("Invalid 'proof' property value, no proof(s) found");
        }

        var event = parser.next();

        if (event == JsonParser.Event.START_OBJECT) {
            return List.of(parseProof(parser, event));
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
            list.add(parseProof(parser, next));
        }
        return list;
    }

    static Map<String, String> parseProof(JsonParser parser, JsonParser.Event parserEvent) {

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
