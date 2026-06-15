package com.apicatalog.cel;

import java.time.Instant;
import java.util.List;
import java.util.Map;

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
