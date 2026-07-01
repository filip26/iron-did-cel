package com.apicatalog.trust.proof;

import com.apicatalog.trust.Proof;

public interface ProofCursor {

    boolean isUnknown();
    
    boolean hasNext();

    void next();

    Proof proof();

}
