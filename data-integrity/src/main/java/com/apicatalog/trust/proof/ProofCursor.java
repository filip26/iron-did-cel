package com.apicatalog.trust.proof;

import com.apicatalog.trust.data.DigestiblePayload;

public interface ProofCursor {

    boolean isUnknown();
    
    boolean hasNext();

    void next();

    Proof proof();

    DigestiblePayload data();

}
