package com.apicatalog.trust.proof;

import com.apicatalog.trust.document.DigestiblePayload;

public interface ProofCursor {

    boolean isUnknown();
    
    boolean hasNext();

    void next();

    Proof proof();

    DigestiblePayload document();

}
