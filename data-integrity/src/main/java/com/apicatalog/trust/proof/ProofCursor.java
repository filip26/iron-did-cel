package com.apicatalog.trust.proof;

public interface ProofCursor {

    boolean isUnknown();
    
    boolean hasNext();

    void next();

    Proof proof();

}
