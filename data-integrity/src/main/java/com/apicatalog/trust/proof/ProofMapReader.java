package com.apicatalog.trust.proof;

import java.util.Collection;
import java.util.Map;

import com.apicatalog.trust.Proof;
import com.apicatalog.trust.document.DigestiblePayload;

public interface ProofMapReader {

    boolean isAccepted(Map<String, Object> proof);

    // reads from tree
    Proof read(
            Collection<String> contexts,
            Map<String, Object> proof,
            byte[] proofPayload,
            DigestiblePayload document);

    String signatureProperty();

}
