package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.di.io.ModelClassifier;
import com.apicatalog.tree.io.TreeIOException;
import com.apicatalog.trust.ProofVerifier;

public class VerifierTest {

    static ProofVerifier VERIFIER = ProofVerifier.createBuilder()

            .build();

    @ParameterizedTest
    @MethodSource({ "resources" })
    void testVerify(String resource) throws Throwable {

        var signed = Resources.getMap(resource);

        var modelClassifier = ModelClassifier.createBuilder();

        var model = modelClassifier.getModel(signed);

        var cursor = model.createCursor(signed);

        if (!cursor.hasNext()) {
            fail("No proof(s) to verify");
            return;
        }

        do {
            var proof = cursor.next();

            var verified = VERIFIER.verify(proof);

            assertTrue(verified);

        } while (!cursor.hasNext());

    }

    static final Stream<String> resources() throws TreeIOException {
        return Resources
                .stream()
                .filter(name -> name.endsWith(".signed.json"));
    }

}
