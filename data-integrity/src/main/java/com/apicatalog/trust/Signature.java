package com.apicatalog.trust;

import com.apicatalog.trust.data.DigestiblePayload;
import com.apicatalog.trust.proof.Proof;

public interface Signature {

    DigestiblePayload data();

    Proof proof();

    byte[] toByteArray();

    String algorithm();
}
