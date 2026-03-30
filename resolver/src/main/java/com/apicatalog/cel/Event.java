package com.apicatalog.cel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonParser;

class Event {

    private final String previousEventHash;
    private final Operation operation;
    private final List<Map<String, String>> proofs;

    public Event(String previousEventHash, Operation operation, List<Map<String, String>> proofs) {
        this.previousEventHash = previousEventHash;
        this.operation = operation;
        this.proofs = proofs;
    }

    public static Event read(JsonParser parser, JsonParser.Event parserEvent) {
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
                operation = Operation.read(parser);
                break;

            case "proof":
                proofs = Proof.readList(parser);
                break;

            case String unknown:
                throw new IllegalArgumentException(
                        "An unknown property '%s' has been detected".formatted(unknown));
            }
        }

        return new Event(previousEventHash, operation, proofs);
    }

    public void addProof(List<Map<String, String>> witnessProofs) {
        proofs.addAll(witnessProofs);
    }

    public void write(JsonGenerator gen) {
        gen.writeStartObject();
        if (previousEventHash != null) {
            gen.write("previousEventHash", previousEventHash);
        }        
        gen.writeKey("operation");
        operation.write(gen);
        if (proofs != null && !proofs.isEmpty()) {
            gen.writeKey("proof");
            if (proofs instanceof ArrayList<Map<String, String>>) {
                gen.writeStartArray();
            }
            for (var proof : proofs) {
                gen.writeStartObject();
                for (var entry : proof.entrySet()) {
                    gen.write(entry.getKey(), entry.getValue());
                }
                gen.writeEnd();
            }
            if (proofs instanceof ArrayList<Map<String, String>>) {
                gen.writeEnd();
            }
        }
        gen.writeEnd();
    }

    public Operation operation() {
        return operation;
    }

    public List<Map<String, String>> proofs() {
        return proofs;
    }

    public String previousEventHash() {
        return previousEventHash;
    }

}
