package com.apicatalog.trust.model;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;

import com.apicatalog.trust.proof.ProofCursor;
import com.apicatalog.trust.proof.ProofGraphCursor.Factory;
import com.apicatalog.trust.proof.ProofGraphReader;
import com.apicatalog.trust.proof.ProofMapReader;

public class GraphModel implements Model {

    private final Factory factory;
    private final String c14n;
    private final Function<Map<String, Object>, Map<String, Entry<Collection<String[]>, byte[]>>> canonize;
    private final Collection<ProofGraphReader> readers;

    public GraphModel(
            Factory factory,
            String c14n,
            Function<Map<String, Object>, Map<String, Entry<Collection<String[]>, byte[]>>> canonize,
            Collection<ProofGraphReader> readers) {
        this.factory = factory;
        this.c14n = c14n;
        this.canonize = canonize;
        this.readers = readers;
    }

    @Override
    public ProofCursor createCursor(Collection<String> context, Map<String, Object> document) {

        var canonized = canonize.apply(document);
        IO.println(canonized);

        // identify proofs
        var proofGraphs = canonized.get("@default").getKey().stream()
                .filter(statement -> "https://w3id.org/security#proof".equals(statement[1]))
                .map(statement -> statement[2]).toList();

        IO.println(proofGraphs);

        if (proofGraphs.isEmpty()) {
            return null;
        }

        var mapping = new ArrayList<Entry<Entry<Collection<String[]>, byte[]>, ProofGraphReader>>(proofGraphs.size());

        boolean cursor = false;

        for (var proofGraph : proofGraphs) {

            ProofGraphReader reader = null;
            var proof = canonized.get(proofGraph);

            for (var proofReader : readers) {
                if (proofReader.isAccepted(proof.getKey())) {
                    reader = proofReader;
                    cursor = true;
                    break;
                }
            }

            mapping.add(new AbstractMap.SimpleImmutableEntry<>(proof, reader));

//            if (proof instanceof Map proofMap) {
//
//                ProofMapReader reader = null;
//
//                for (var proofReader : proofReaders) {
//                    if (proofReader.isAccepted((Map<String, Object>) proofMap)) {
//                        reader = proofReader;
//                        cursor = true;
//                        break;
//                    }
//                }
//
//                Map<String, Object> map = proofMap;
//
//                if (!map.containsKey("@context")) {
//                    map = new HashMap<String, Object>(proofMap);
//                    map.put("@context", context);
//                }
//
//                mapping.add(new AbstractMap.SimpleImmutableEntry<>(map, reader));
//            }
        }

        if (!cursor) {
            return null;
        }

        return factory.newInstance(this, document, mapping);
    }
}
