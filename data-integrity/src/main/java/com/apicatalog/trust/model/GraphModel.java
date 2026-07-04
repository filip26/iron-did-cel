package com.apicatalog.trust.model;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

import com.apicatalog.trust.proof.ProofCursor;
import com.apicatalog.trust.proof.ProofGraphCursor.Factory;
import com.apicatalog.trust.proof.ProofGraphReader;

public class GraphModel implements Model {

    @FunctionalInterface
    public interface QuadConsumer {
        void accept(
                String subject,
                String predicate,
                String object,
                String datatype,
                String language,
                String direction,
                String graph);
    }

    public interface Canonizer {
        QuadConsumer consumer();

        byte[] canonize();
    }

    // Map<String, Collection<String[]

    private final Factory cursorFactory;
    private final String c14n;
    private final BiConsumer<Map<String, Object>, QuadConsumer> tordf;
    private final Supplier<Canonizer> canonizeFactory;
    private final Collection<ProofGraphReader> readers;

    public GraphModel(
            Factory factory,
            String c14n,
            BiConsumer<Map<String, Object>, QuadConsumer> tordf,
            Supplier<Canonizer> canonizeFactory,
            Collection<ProofGraphReader> readers) {
        this.cursorFactory = factory;
        this.c14n = c14n;
        this.tordf = tordf;
        this.canonizeFactory = canonizeFactory;
        this.readers = readers;
    }

    @Override
    public String c14n() {
        return c14n;
    }

    @Override
    public ProofCursor createCursor(Collection<String> context, Map<String, Object> document) {

        var graphBuilder = new GraphBuilder();

        tordf.accept(document, graphBuilder);

        var graphs = graphBuilder.get();

//        var canonized = rdfc.canonize();

//        IO.println(canonized);

        // identify proofs
        var proofGraphs = graphs.get("@default").stream()
                .filter(statement -> "https://w3id.org/security#proof".equals(statement[1]))
                .map(statement -> statement[2]).toList();

        IO.println(proofGraphs);

        if (proofGraphs.isEmpty()) {
            return null;
        }

        var mapping = new ArrayList<Entry<Collection<String[]>, ProofGraphReader>>(proofGraphs.size());

        boolean cursor = false;

        for (var proofGraph : proofGraphs) {

            ProofGraphReader reader = null;
            var proof = graphs.get(proofGraph);

            for (var proofReader : readers) {
                if (proofReader.isAccepted(proof)) {
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

//        return null;
        return cursorFactory.newInstance(this, graphs.get("@default"), mapping);
    }

    private static class GraphBuilder implements QuadConsumer {

        private Map<String, Collection<String[]>> graphMap = new HashMap<>();
//        private QuadConsumer c14nConsumer;

//        public GraphBuilder(QuadConsumer c14nConsumer) {
//            this.c14nConsumer = c14nConsumer;
//        }

        public Map<String, Collection<String[]>> get() {
            return graphMap;
        }

        @Override
        public void accept(
                String subject,
                String predicate,
                String object,
                String datatype,
                String language,
                String direction,
                String graph) {

            var key = graph;

            if (key == null) {
                key = "@default";
            }

            graphMap.computeIfAbsent(key, (_) -> new ArrayList<String[]>())
                    .add(new String[] {
                            subject, predicate, object, datatype, language, direction
                    });
        }

    }

    public Canonizer newCanonizer() {
        return canonizeFactory.get();
    }
}
