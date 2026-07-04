package com.apicatalog.trust.proof;

import java.util.Collection;

import com.apicatalog.trust.data.Data;

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

    boolean isAccepted(Collection<String[]> proof);

    // reads from n-quads
    Proof read(
            Collection<String[]> proof,
            byte[] proofPayload,
            Data data);

    String signatureTerm();

}
