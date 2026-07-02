package com.apicatalog.trust.proof;

import java.util.Collection;
import java.util.Map;

import com.apicatalog.trust.model.GraphModel;

/*
 * 1. JSON-LD expansion + type, uri map
 * 2. separating proof
 * 3. instantiate document function -> out
 * 4. instantiate proof(index) function -> out
 */
public class ProofGraphCursor implements ProofCursor {

    @FunctionalInterface
    public interface Factory {
        ProofGraphCursor newInstance(
                GraphModel model,
                Map<String, Object> document,
                Collection<Object> proofs,
                Collection<ProofGraphReader> proofReaders);
    }

    public static ProofGraphCursor newInstance(
            GraphModel model,
            Map<String, Object> document,
            Collection<Object> proofs,
            Collection<ProofGraphReader> proofReaders) {
        return new ProofGraphCursor();
    }

    @Override
    public boolean isUnknown() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean hasNext() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void next() {
        // TODO Auto-generated method stub
        
    }

    @Override
    public Proof proof() {
        // TODO Auto-generated method stub
        return null;
    }

//    public Entry<Supplier<DigestiblePayload>, IntFunction<Collection<Proof>>> payload(
//            Collection<String> contexts,
//            Map<String, Object> document) {
//        return null;
//    }

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
