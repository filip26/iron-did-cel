package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
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
import com.apicatalog.trust.model.Model;
import com.apicatalog.trust.model.ModelResolver;
import com.apicatalog.trust.proof.Proof;
import com.apicatalog.trust.proof.ProofMapCursor;
import com.fasterxml.jackson.core.JsonFactory;

public class VerifierTest {

    static Model MODEL_1 = DataIntegrity.createTypeModelBuilder("JCS")
            .proof(CryptoSuites.EDDSA_JCS_2022)
            .proof(CryptoSuites.ECDSA_JCS_2019_P256)
            .proof(CryptoSuites.ECDSA_JCS_2019_P384)
            .c14n(Jcs::canonize)
            .processor(ProofMapCursor::new)
            .build();

    static Model MODEL_2 = DataIntegrity.createGraphModelBuilder("RDFC")
            .proof(CryptoSuites.EDDSA_RDFC_2022)
            .proof(CryptoSuites.ECDSA_RDFC_2019_P256)
            .proof(CryptoSuites.ECDSA_RDFC_2019_P384)
            .proof(Ed25519Signature2020.createReader())
//            .c14n(Jcs::canonize)
//            .processor(ProofGraphCursor::new)
            .build();

    static ModelResolver MODEL_RESOLVER = ModelResolver.createBuilder()
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

    static ProofVerifier PROOF_VERIFIER = ProofVerifier.createBuilder()
            .proof(DataIntegrityProof.TYPE_NAME, DID_KEY_RESOLVER, BcEd25519Verifier.getInstance()::verify)
            .proof(Ed25519Signature2020.TYPE_NAME, DID_KEY_RESOLVER, BcEd25519Verifier.getInstance()::verify)
            .build();

    @ParameterizedTest
    @MethodSource({ "resources" })
    void testVerify(String resource) throws Throwable {

        var signed = Resources.getMap(resource);
        rdfc(signed);
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

            do {
                cursor.next();

                assertFalse(cursor.isUnknown());

                var proof = cursor.proof();

                var verified = PROOF_VERIFIER.verify(proof);

                assertTrue(verified);

                proofs.add(proof);

            } while (cursor.hasNext());
        }

        assertFalse(proofs.isEmpty());
    }

    static final Stream<String> resources() {
        return Resources
                .stream()
                .filter(name -> name.endsWith(".signed.json"));
    }

    static final Entry<byte[], Map<String, Object>> rdfc(Map<String, ?> document)
            throws IOException, JsonLdError, RdfConsumerException {

        // TODO temporary, remove with Titanium v2.x.x
        var bos = new ByteArrayOutputStream();
        try (var emitter = Jackson2Emitter.createEmitter(bos, JsonFactory.builder().build())) {
            Tree.write(document, emitter);
        }

        var toRdf = JsonLd.toRdf(JsonDocument.of(new ByteArrayInputStream(bos.toByteArray())));

        var canon = RdfCanon.create("SHA-256");
        toRdf.provide(canon);

        var consumer = new QuadConsumer();

        canon.provide(consumer);

        System.out.println(new String(consumer.documentC14n.toByteArray()));
        System.out.println(consumer.proofs.values());
        System.out.println(consumer.proofsC14n.values());
        // return Map.entry(bos.toByteArray();
        return null;
    }

    // TODO remove with rdf-api 2.0.0
    static class QuadConsumer implements RdfQuadConsumer {

        Collection<String[]> document = new ArrayList<String[]>();
        ByteArrayOutputStream documentC14n = new ByteArrayOutputStream();

        Map<String, Collection<String[]>> proofs = new LinkedHashMap<>();
        Map<String, ByteArrayOutputStream> proofsC14n = new HashMap<>();

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
                var doc = document;
                var c14n = documentC14n;

                if (graph != null) {
                    doc = proofs.computeIfAbsent(graph, (_) -> new ArrayList<>());
                    c14n = proofsC14n.computeIfAbsent(graph, (_) -> new ByteArrayOutputStream());
                }

                doc.add(new String[] { subject, predicate, object, datatype, language, direction, graph });

                c14n.write(NQuadsWriter.nquad(subject, predicate, object, datatype, language, direction, graph)
                        .getBytes(StandardCharsets.UTF_8));

            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            return this;
        }

    }
}
