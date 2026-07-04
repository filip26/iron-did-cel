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
            System.out.println("> " + subject + ", " + predicate + ", " + object + "," + graph);

            var key = graph;

            if (key == null) {
                key = "@default";
            }

            graphMap.computeIfAbsent(key, (_) -> new ArrayList<String[]>())
                    .add(new String[] {
                            subject, predicate, object, datatype, language, direction, graph
                    });
        }

    }

//    // TODO remove with rdf-api 2.0.0
//    static class QuadConsumer {
//
//        Map<String, Collection<String[]>> documents = new LinkedHashMap<>();
//        Map<String, ByteArrayOutputStream> c14n = new HashMap<>();
//
//        public void quad(
//                String subject,
//                String predicate,
//                String object,
//                String datatype,
//                String language,
//                String direction,
//                String graph) {
//
//            try {
//                var graphName = graph != null ? graph : "@default";
//
//                documents.computeIfAbsent(graphName, (_) -> new ArrayList<>())
//                        .add(new String[] { subject, predicate, objectOrLangString(object, language, direction),
//                                datatype });
//
//                c14n.computeIfAbsent(graphName, (_) -> new ByteArrayOutputStream())
//                        .write(NQuadsWriter.nquad(subject, predicate, object, datatype, language, direction, graph)
//                                .getBytes(StandardCharsets.UTF_8));
//
//            } catch (IOException e) {
//                throw new IllegalStateException(e);
//            }
//
//        }
//
//        Map<String, Entry<Collection<String[]>, byte[]>> get() {
//
//            var map = new LinkedHashMap<String, Entry<Collection<String[]>, byte[]>>();
//
//            for (var entry : documents.entrySet()) {
//                map.put(entry.getKey(),
//                        Map.entry(entry.getValue(), c14n.get(entry.getKey()).toByteArray()));
//            }
//
//            return map;
//
//        }
//
//    }
//
//    // FIXME temporary, waits for n-quads 3.0.0, then remove
//    static String objectOrLangString(String literal, String language, String direction) {
//        if (direction != null) {
//            return "\"" + escape(literal) + "\"@"
//                    + (language != null ? language : "und")
//                    + "--"
//                    + direction;
//        }
//        if (language != null) {
//            return "\"" + escape(literal) + "\"@" + language;
//        }
//        return literal;
//    }
//
//    public static final String escape(String value) {
//
//        final StringBuilder escaped = new StringBuilder();
//
//        int[] codePoints = value.codePoints().toArray();
//
//        for (int ch : codePoints) {
//
//            if (ch == 0x9) {
    ////                escaped.append("\\t");
//
//            } else if (ch == 0x8) {
    ////                escaped.append("\\b");
//
    //// } else if (ch == 0xa) { / escaped.append("\\n");
//
    //// } else if (ch == 0xd) { / escaped.append("\\r");
//
    //// } else if (ch == 0xc) { / escaped.append("\\f");
//
//            } else if (ch == '"') {
//                escaped.append("\\\"");
//
//            } else if (ch == '\\') {
//                escaped.append("\\\\");
//
    //// } else if (ch >= 0x0 && ch <= 0x1f || ch == 0x7f) { /
    /// escaped.append(String.format("\\u%04X", ch));
//
//            } else {
//                escaped.appendCodePoint(ch);
//            }
//        }
//        return escaped.toString();
//    }
}
