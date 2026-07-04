package com.apicatalog.trust.proof;

import com.apicatalog.trust.data.DigestiblePayload;

public interface ProofCursor {

    boolean isUnknown();

    boolean next();

    Proof proof();

    DigestiblePayload data();
}
