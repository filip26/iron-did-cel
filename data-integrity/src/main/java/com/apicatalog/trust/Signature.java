package com.apicatalog.trust;

import com.apicatalog.trust.document.DigestiblePayload;
import com.apicatalog.trust.proof.Proof;

public interface Signature {

    DigestiblePayload document();

    Proof proof();

    byte[] toByteArray();

    String algorithm();
}
