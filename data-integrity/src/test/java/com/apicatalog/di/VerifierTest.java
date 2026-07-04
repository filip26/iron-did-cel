package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.crypto.bc.BcEd25519Verifier;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.di.proof.Ed25519Signature2020;
import com.apicatalog.di.suite.CryptoSuites;
import com.apicatalog.jcs.Jcs;
import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.lang.Keywords;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.rdf.api.RdfConsumerException;
import com.apicatalog.rdf.api.RdfQuadConsumer;
import com.apicatalog.rdf.canon.RdfCanon;
import com.apicatalog.rdf.nquads.NQuadsWriter;
import com.apicatalog.tree.io.Tree;
import com.apicatalog.tree.io.jakcson.Jackson2Emitter;
import com.apicatalog.trust.MethodResolver;
import com.apicatalog.trust.ProofVerifier;
import com.apicatalog.trust.model.GraphModel;
import com.apicatalog.trust.model.GraphModel.Canonizer;
import com.apicatalog.trust.model.GraphModel.QuadConsumer;
import com.apicatalog.trust.model.Model;
import com.apicatalog.trust.model.ModelResolver;
import com.apicatalog.trust.proof.Proof;
import com.apicatalog.trust.proof.ProofGraphCursor;
import com.apicatalog.trust.proof.ProofMapCursor;
import com.fasterxml.jackson.core.JsonFactory;

public class VerifierTest {

    static Model MODEL_1 = DataIntegrity.newTypeModelBuilder("JCS")
            .proof(CryptoSuites.EDDSA_JCS_2022)
            .proof(CryptoSuites.ECDSA_JCS_2019_P256)
            .proof(CryptoSuites.ECDSA_JCS_2019_P384)
            .c14n(Jcs::canonize)
            .processor(ProofMapCursor::new)
            .build();

    static Model MODEL_2 = DataIntegrity.newGraphModelBuilder("RDFC")
            .proof(CryptoSuites.EDDSA_RDFC_2022)
            .proof(CryptoSuites.ECDSA_RDFC_2019_P256)
            .proof(CryptoSuites.ECDSA_RDFC_2019_P384)
//TODO            .proof(Ed25519Signature2020.createReader())
            .tordf(VerifierTest::tordfc)
            .c14n(VerifierTest::newRdfc)
            .processor(ProofGraphCursor::new)
            .build();

    static ModelResolver MODEL_RESOLVER = ModelResolver.newBuilder()
            // accept any context - for test purposes only
            .model(Predicate.not(Collection::isEmpty), MODEL_1, MODEL_2)
            .build();

    static MethodResolver DID_KEY_RESOLVER = proof -> {
        if (!proof.verificationMethod().startsWith("did:key:")) {
            return null; // TODO
        }

        var key = MultibaseDecoder.getInstance().decode(
                proof.verificationMethod().substring("did:key:".length(), proof.verificationMethod().indexOf('#')));

        var codec = MulticodecDecoder.getInstance().getCodec(key).orElseThrow();

        return codec.decode(key);

    };

    static ProofVerifier PROOF_VERIFIER = ProofVerifier.newBuilder()
            .proof(DataIntegrityProof.TYPE_NAME, DID_KEY_RESOLVER, BcEd25519Verifier.getInstance()::verify)
            .proof(Ed25519Signature2020.TYPE_NAME, DID_KEY_RESOLVER, BcEd25519Verifier.getInstance()::verify)
            .build();

    @ParameterizedTest
    @MethodSource({ "resources" })
    void testVerify(String resource) throws Throwable {

        var signed = Resources.getMap(resource);

        var contexts = MODEL_RESOLVER.getContexts(signed);

        var models = MODEL_RESOLVER.resolve(contexts, signed);

        assertFalse(models.isEmpty());

        var proofs = new ArrayList<Proof>();

        for (var model : models) {

            var cursor = model.createCursor(contexts, signed);

            if (cursor == null) {
                continue;
            }

            if (!cursor.hasNext()) {
                fail("No proof(s) to verify");
                return;
            }

            var doc = cursor.document();
            
            var x = MessageDigest.getInstance("SHA-256");
            x.update(doc.canonicalPayload());
            IO.println(HexFormat.of().formatHex(x.digest()));

            
            do {
                cursor.next();
                
                assertFalse(cursor.isUnknown());

                var proof = cursor.proof();
                
                x.update(proof.canonicalPayload());
                IO.println(HexFormat.of().formatHex(x.digest()));

                
                
                var verified = PROOF_VERIFIER.verify(proof);

                IO.println("> " + HexFormat.of().formatHex(doc.digest("SHA-256")));

                
                assertTrue(verified);

                proofs.add(proof);

            } while (cursor.hasNext());

            // no unknown proofs, the model has processed all proofs, terminate
            break;
        }

        assertFalse(proofs.isEmpty());
    }

    static final Stream<String> resources() {
        return Resources
                .stream()
                .filter(name -> name.endsWith(".signed.json"))
                .sorted();
    }

    static final void tordfc(Map<String, Object> document, final GraphModel.QuadConsumer consumer) {
        try {
            // TODO temporary, remove with Titanium v2.x.x
            var bos = new ByteArrayOutputStream();
            try (var emitter = Jackson2Emitter.newEmitter(bos, JsonFactory.builder().build())) {
                Tree.write(document, emitter);
            }

            var toRdf = JsonLd.toRdf(JsonDocument.of(new ByteArrayInputStream(bos.toByteArray())))
                    .loader(ContextLoader.getInstance());

            // TODO remove with rdf-api 2.0.0
            toRdf.provide(new RdfQuadConsumer() {

                @Override
                public RdfQuadConsumer quad(String subject, String predicate, String object, String datatype,
                        String language,
                        String direction, String graph) {

                    consumer.accept(subject, predicate, object, datatype, language, direction, graph);
                    return this;
                }
            });

        } catch (IOException | JsonLdError e) {
            throw new IllegalStateException(e);
        }
    }

    static final RdfcPrcessor newRdfc() {
        return new RdfcPrcessor(); // TODO reuse one instance across
    }

    static class RdfcPrcessor implements Canonizer {

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();

        final RdfCanon canon = RdfCanon.create("SHA-256");

        @Override
        public byte[] canonize() {

            bos.reset();

            canon.provide(line -> {
                try {
                    bos.write(line.getBytes(StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });

            return bos.toByteArray();
        }

        @Override
        public QuadConsumer consumer() {
            // TODO remove with rdf-api 2.0.0
            return new GraphModel.QuadConsumer() {

                @Override
                public void accept(
                        String subject,
                        String predicate,
                        String object,
                        String datatype,
                        String language,
                        String direction,
                        String graph) {

                    canon.quad(subject, predicate, object, datatype, language, direction, graph);
                }
            };
        }

    }

    static final Map<String, Entry<Collection<String[]>, byte[]>> rdfc2(Map<String, Object> document) {

        try {
            // TODO temporary, remove with Titanium v2.x.x
            var bos = new ByteArrayOutputStream();
            try (var emitter = Jackson2Emitter.newEmitter(bos, JsonFactory.builder().build())) {
                Tree.write(document, emitter);
            }

            var toRdf = JsonLd.toRdf(JsonDocument.of(new ByteArrayInputStream(bos.toByteArray())))
                    .loader(ContextLoader.getInstance());

            var canon = RdfCanon.create("SHA-256");
            toRdf.provide(canon);

            var consumer = new QuadConsumer2();

            canon.provide(consumer);

//            System.out.println(consumer.documents.values());
//            System.out.println(consumer.c14n.values());
            return consumer.get();

        } catch (IOException | JsonLdError | RdfConsumerException e) {
            throw new IllegalStateException(e);
        }
    }

    // TODO remove with rdf-api 2.0.0
    static class QuadConsumer2 implements RdfQuadConsumer {

        Map<String, Collection<String[]>> documents = new LinkedHashMap<>();
        Map<String, ByteArrayOutputStream> c14n = new HashMap<>();

        @Override
        public RdfQuadConsumer quad(
                String subject,
                String predicate,
                String object,
                String datatype,
                String language,
                String direction,
                String graph) throws RdfConsumerException {

            try {
                var graphName = graph != null ? graph : Keywords.DEFAULT;

                documents.computeIfAbsent(graphName, (_) -> new ArrayList<>())
                        .add(new String[] { subject, predicate, objectOrLangString(object, language, direction),
                                datatype });

                c14n.computeIfAbsent(graphName, (_) -> new ByteArrayOutputStream())
                        .write(NQuadsWriter.nquad(subject, predicate, object, datatype, language, direction, graph)
                                .getBytes(StandardCharsets.UTF_8));

            } catch (IOException e) {
                throw new IllegalStateException(e);
            }

            return this;
        }

        Map<String, Entry<Collection<String[]>, byte[]>> get() {

            var map = new LinkedHashMap<String, Entry<Collection<String[]>, byte[]>>();

            for (var entry : documents.entrySet()) {
                map.put(entry.getKey(),
                        Map.entry(entry.getValue(), c14n.get(entry.getKey()).toByteArray()));
            }

            return map;

        }

    }

    // FIXME temporary, waits for n-quads 3.0.0, then remove
    static String objectOrLangString(String literal, String language, String direction) {
        if (direction != null) {
            return "\"" + escape(literal) + "\"@"
                    + (language != null ? language : "und")
                    + "--"
                    + direction;
        }
        if (language != null) {
            return "\"" + escape(literal) + "\"@" + language;
        }
        return literal;
    }

    public static final String escape(String value) {

        final StringBuilder escaped = new StringBuilder();

        int[] codePoints = value.codePoints().toArray();

        for (int ch : codePoints) {

            if (ch == 0x9) {
//                escaped.append("\\t");

            } else if (ch == 0x8) {
//                escaped.append("\\b");

//            } else if (ch == 0xa) {
//                escaped.append("\\n");

//            } else if (ch == 0xd) {
//                escaped.append("\\r");

//            } else if (ch == 0xc) {
//                escaped.append("\\f");

            } else if (ch == '"') {
                escaped.append("\\\"");

            } else if (ch == '\\') {
                escaped.append("\\\\");

//            } else if (ch >= 0x0 && ch <= 0x1f || ch == 0x7f) {
//                escaped.append(String.format("\\u%04X", ch));

            } else {
                escaped.appendCodePoint(ch);
            }
        }
        return escaped.toString();
    }

}
