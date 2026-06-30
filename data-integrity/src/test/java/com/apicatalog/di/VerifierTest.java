package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.di.io.Model;
import com.apicatalog.di.io.ModelResolver;
import com.apicatalog.di.io.TypeSpecificModel;
import com.apicatalog.di.io.TypeSpecificProcessor;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.di.proof.Ed25519Signature2020;
import com.apicatalog.di.suite.CryptoSuites;
import com.apicatalog.jcs.Jcs;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.trust.MethodResolver;
import com.apicatalog.trust.Proof;
import com.apicatalog.trust.ProofVerifier;

public class VerifierTest {

    static Model MODEL_1 = TypeSpecificModel.createBuilder("JCS")
            .proof(CryptoSuites.ECDSA_JCS_2019_P256)
            .c14n(Jcs::canonize)
            .processor(TypeSpecificProcessor::newInstance)
            .build();

    static ModelResolver MODEL_RESOLVER = ModelResolver.createBuilder()
            // accept any context - for test purposes only
            .model(Predicate.not(Collection::isEmpty), MODEL_1)
//            .proof(CryptoSuites.ECDSA_JCS_2019_P256)
//            .proof(Ed25519Signature2020.createReader())
//            .c14n("JCS", Jcs::canonize)
//            .processor("JCS", TypeSpecificProcessor::newInstance)
//            .processor("RDFC", GraphProcessor::newInstance)
            .build();

    static MethodResolver DID_KEY_RESOLVER = (proof, _) -> {
        if (!proof.verificationMethod().startsWith("did:key:")) {
            return null; // TODO
        }

        var key = MultibaseDecoder.getInstance().decode(
                proof.verificationMethod().substring("did:key:".length(), proof.verificationMethod().indexOf('#')));

        var codec = MulticodecDecoder.getInstance().getCodec(key).orElseThrow();

        return codec.decode(key);

    };

    static ProofVerifier PROOF_VERIFIER = ProofVerifier.createBuilder()
            .accept(DataIntegrityProof.TYPE_NAME, DID_KEY_RESOLVER)
            .accept(Ed25519Signature2020.TYPE_NAME, DID_KEY_RESOLVER)
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

            var processor = model.createProcessor(contexts, signed);

            if (processor == null) {
                continue;
            }

            var cursor = processor.createProofCursor();

            assertNotNull(cursor);

            if (!cursor.hasNext()) {
                fail("No proof(s) to verify");
                return;
            }

            do {
                cursor.next();

                var proof = cursor.proof();

                var verified = PROOF_VERIFIER.verify(proof);

                assertTrue(verified);

                proofs.add(proof);

            } while (!cursor.hasNext());
        }

        assertFalse(proofs.isEmpty());
    }

    static final Stream<String> resources() {
        return Resources
                .stream()
                .filter(name -> name.endsWith(".signed.json"));
    }

}
