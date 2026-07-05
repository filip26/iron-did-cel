package com.apicatalog.trust.proof;

import java.util.Collection;

import com.apicatalog.trust.data.Data;

public interface ProofGraphReader {

    boolean isAccepted(Collection<String[]> proof);

    // reads from n-quads
    Proof read(
            Collection<String[]> proof,
            Data data);

}
