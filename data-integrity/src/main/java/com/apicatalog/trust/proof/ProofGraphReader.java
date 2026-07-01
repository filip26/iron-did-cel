package com.apicatalog.trust.proof;

import java.util.Collection;
import java.util.Map;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.DigestiblePayload;

public interface ProofGraphReader {

    @FunctionalInterface
    interface NQuadsConsumer {
        void quad(
                String subject,
                String predicate,
                String object,
                String datatype,
                String language,
                String direction,
                String graph);
    }

    boolean isAccepted(Map<String, Object> proof);

//    // reads from flattened n-quads
//    Proof read(
//            Collection<String> contexts,
//            Map<String, Object> proof,
//            byte[] proofPayload,
//            DigestiblePayload document);

    String signatureProperty();

}
