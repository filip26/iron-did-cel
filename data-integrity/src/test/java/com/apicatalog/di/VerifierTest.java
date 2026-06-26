package com.apicatalog.di;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.apicatalog.di.io.ModelResolver;
import com.apicatalog.di.proof.DataIntegrityProof;
import com.apicatalog.di.proof.Ed25519Signature2020;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.trust.MethodResolver;
import com.apicatalog.trust.ProofVerifier;

public class VerifierTest {

    static MethodResolver DID_KEY_RESOLVER = (proof, algorithm) -> {
        if (!proof.verificationMethod().startsWith("did:key:")) {
            return null; // TODO
        }

        var key = MultibaseDecoder.getInstance().decode(
                proof.verificationMethod().substring("did:key:".length(), proof.verificationMethod().indexOf('#')));

        var codec = MulticodecDecoder.getInstance().getCodec(key).orElseThrow();
        
        return codec.decode(key);
        
    };

    static ProofVerifier VERIFIER = ProofVerifier.createBuilder()
            .accept(DataIntegrityProof.TYPE_NAME, DID_KEY_RESOLVER)
            .accept(Ed25519Signature2020.TYPE_NAME, DID_KEY_RESOLVER)
            .build();

    @ParameterizedTest
    @MethodSource({ "resources" })
    void testVerify(String resource) throws Throwable {

        var signed = Resources.getMap(resource);

        var modelResolver = ModelResolver.createBuilder()
                .model(null, null)
                ;
        
        var model = modelResolver.getModel(signed);
        
        var cursor = model.createCursor(signed);
        
        assertNotNull(cursor);
        
        if (!cursor.hasNext()) {
            fail("No proof(s) to verify");
            return;
        }

        do {
            var proof = cursor.next();

            var verified = VERIFIER.verify(proof);

            assertTrue(verified);

        } while (!cursor.hasNext());        

        /*
         * 
         *  var processor = DocumentProcessor.get(document);
         *  
         *  var contexts = processor.contexts();
         *  
         *  var cursor = processor.createCursor();
         *  
         *  
         * 
         * 
         */
//        
//        var processor = DocumentProcessor.createBuilder()
//                
//                .model(DataIntegrityModel.createBuilder()
//                        .proof(Ed25519Signature2020.TYPE, Ed25519Signature2020::createProof)
//                        .cryptosuite(CryptoSuites.EDDSA_JCS_2022)   // alias for
//                        .cryptosuite(CryptoSuites.EDDSA_RDFC_2022)
//                        .build()
//                       
//                        );
//                .build();
//
//        var model = processor.getModel(signed);
//
//        var cursor = model.createCursor(signed);
//

    }

    static final Stream<String> resources() {
        return Resources
                .stream()
                .filter(name -> name.endsWith(".signed.json"));
    }

}
