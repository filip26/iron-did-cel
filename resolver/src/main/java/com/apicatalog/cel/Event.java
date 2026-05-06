package com.apicatalog.cel;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.json.stream.JsonGenerator;
import jakarta.json.stream.JsonParser;

public class Event {

    private final String previousEventHash;
    private final Operation operation;
    private final List<Map<String, String>> proofs;

    private Instant created;

    public Event(String previousEventHash, Operation operation, List<Map<String, String>> proofs) {
        this.previousEventHash = previousEventHash;
        this.operation = operation;
        this.proofs = proofs;
        this.created = null;
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

    public Instant created() {
        if (created == null) {
            for (var proof : proofs) {
                var createdString = proof.get("created");
                if (createdString != null) {
                    var last = Instant.parse(createdString);
                    if (created == null || last.isBefore(created)) {
                        created = last;
                    }
                }
            }
        }
        return created;
    }
}
