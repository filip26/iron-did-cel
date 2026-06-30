package com.apicatalog.di.io;

import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.IntFunction;
import java.util.function.Supplier;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.DigestiblePayload;
import com.apicatalog.trust.proof.ProofMapReader;

/*
 * 1. JSON-LD expansion + type, uri map
 * 2. separating proof
 * 3. instantiate document function -> out
 * 4. instantiate proof(index) function -> out
 */
public class GraphProcessor {

    public interface Factory {
        GraphProcessor newInstance(
                GraphModel model,
                Map<String, Object> document,
                Collection<Object> proofs,
                Collection<ProofMapReader> proofReaders);
    }

    public static         GraphProcessor newInstance(
            GraphModel model,
            Map<String, Object> document,
            Collection<Object> proofs,
            Collection<ProofMapReader> proofReaders) {
        return new GraphProcessor();
    }
    
    public Entry<Supplier<DigestiblePayload>, IntFunction<Collection<Proof>>> payload(Collection<String> contexts,
            Map<String, Object> document) {
        return null;
    }

    // canonicalBytes, [subject, predicate, object, datatype, language, direction]>
//    Entry<byte[], Collection<String[]>> canonize();
//
//    public static GraphProcessor newInstance(Collection<String> contexts, Map<String, Object> document) {
//        
//        
//        return null;
//    }
//

}
